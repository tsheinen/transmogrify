use crate::{get_functions, Function};
use capstone::prelude::*;
use capstone::{Capstone, Insn};
use r2pipe::{open_pipe, R2Pipe};
use std::collections::HashMap;
use tui::widgets::ListState;

pub enum SelectedColumn {
    Function,
    Hex,
    Disasm,
}

impl SelectedColumn {
    pub fn editable(&self) -> bool {
        match self {
            Self::Function => false,
            Self::Hex | Self::Disasm => true,
        }
    }
}

pub enum Mode {
    Viewing,
    Editing,
}

pub fn disasm(bytes: &[u8]) -> Vec<(Vec<u8>, String)> {
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
        .expect("failed to create capstone object");
    let insns = cs.disasm_all(bytes, 0x0).expect("disasm to work?");
    insns
        .iter()
        .map(|x| {
            (
                x.bytes().iter().cloned().collect::<Vec<_>>(),
                format!(
                    "{} {}",
                    x.mnemonic().unwrap_or(""),
                    x.op_str().unwrap_or("")
                ),
            )
        })
        .collect()
}

pub fn to_hexstring(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|x| format!("{:02x}", x))
        .collect::<Vec<String>>()
        .join(" ")
}
pub fn from_hexstring(str: String) -> Vec<u8> {
    str.chars()
        .filter(|x| *x != ' ')
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|x| x.iter().collect::<String>().parse::<u8>().unwrap_or(0))
        .collect()
}

pub fn asm(instr: String) -> Result<Vec<u8>, keystone::Error> {
    use keystone::{Arch, Keystone, OptionType};

    let engine =
        Keystone::new(Arch::X86, keystone::MODE_64).expect("Could not initialize Keystone engine");
    engine
        .option(OptionType::SYNTAX, keystone::OPT_SYNTAX_NASM)
        .expect("Could not set option to nasm syntax");
    engine.asm(instr, 0).map(|x| x.bytes)
}

pub struct Application {
    pub state: ListState,
    pub functions: Vec<Function>,
    pub bytes: HashMap<String, Vec<String>>,
    pub disasm: HashMap<String, Vec<String>>,
    pub function_state: ListState,
    pub editor_state: ListState,
    pub selected: SelectedColumn,
    pub mode: Mode,
    pub cursor_index: isize,
    pub column_width: isize,
}

impl Application {
    pub fn new<P: AsRef<str>>(path: P) -> Self {
        // disassemble this with capstone

        let mut r2p = open_pipe!(Some(&path)).unwrap();
        r2p.cmd("aaa").unwrap();
        let x = r2p.cmd("aflj").unwrap();
        let functions = if let Ok(json) = serde_json::from_str::<Vec<Function>>(&x) {
            json
        } else {
            vec![]
        };

        let program = std::fs::read(path.as_ref()).unwrap();

        let (bytes, disasm): (Vec<(String, Vec<String>)>, Vec<(String, Vec<String>)>) = functions
            .iter()
            .map(|function| {
                let (bytes, disasm): (Vec<Vec<u8>>, Vec<String>) =
                    disasm(&program[function.offset..function.offset + function.size])
                        .into_iter()
                        .unzip();
                (
                    (
                        function.name.clone(),
                        bytes.iter().map(|x| to_hexstring(x)).collect(),
                    ),
                    (function.name.clone(), disasm),
                )
            })
            .unzip();

        Application {
            state: ListState::default(),
            functions,
            bytes: bytes.into_iter().collect(),
            disasm: disasm.into_iter().collect(),
            function_state: ListState::default(),
            editor_state: ListState::default(),
            selected: SelectedColumn::Function,
            mode: Mode::Viewing,
            cursor_index: 0,
            column_width: 0,
        }
    }

    pub fn get(&self, function: String, i: usize) -> Option<(&String, &String)> {
        if i < self.bytes.len() && self.bytes.contains_key(&function) {
            let bytes = self.bytes.get(&function).unwrap();
            let disasm = self.disasm.get(&function).unwrap();
            Some((&bytes[i], &disasm[i]))
        } else {
            None
        }
    }

    pub fn set_bytes(&mut self, function: String, i: usize, data: Vec<u8>) -> Result<(), String> {
        // set bytes and update disassembly, return error if an instruction can't be found
        let bytes_data = self
            .bytes
            .get_mut(&function)
            .ok_or("function doesn't exist")?;
        let disasm_data = self
            .disasm
            .get_mut(&function)
            .ok_or("function doesn't exist")?;
        if i < bytes_data.len() {
            let (bytes, instr) = disasm(&data)
                .first()
                .cloned()
                .ok_or(format!("No instructions found"))?;
            bytes_data[i] = to_hexstring(&bytes);
            disasm_data[i] = instr.clone();
            Ok(())
        } else {
            Err(format!("i outside of range"))
        }
    }

    pub fn set_asm(&mut self, function: String, i: usize, data: String) -> Result<(), String> {
        // set disasm and assemble (keystone maybe?), return error if it can't be assembled
        let bytes = self
            .bytes
            .get_mut(&function)
            .ok_or("function doesn't exist")?;
        let disasm = self
            .disasm
            .get_mut(&function)
            .ok_or("function doesn't exist")?;
        if i < bytes.len() {
            bytes[i] = to_hexstring(&asm(data.clone()).expect("asm to work"));
            disasm[i] = data;
            Ok(())
        } else {
            Err(format!("i outside of range"))
        }
    }

    pub fn values(&self, function: String) -> impl Iterator<Item = (String, String)> {
        let bytes = self.bytes.get(&function).cloned().unwrap_or(vec![]);
        let disasm = self.disasm.get(&function).cloned().unwrap_or(vec![]);
        bytes.into_iter().zip(disasm.into_iter())
    }

    pub fn get_current_function(&self) -> &Function {
        &self.functions[self.function_state.selected().unwrap_or(0)]
    }

    pub fn next(&mut self) {
        self.mutate_selector(1)
    }

    pub fn previous(&mut self) {
        self.mutate_selector(-1)
    }

    fn mutate_selector(&mut self, val: isize) {
        let current_func_name = self.get_current_function().name.clone();
        let len = match self.selected {
            SelectedColumn::Function => self.functions.len() as isize,
            SelectedColumn::Hex | SelectedColumn::Disasm => self
                .bytes
                .get(&current_func_name)
                .map(|x| x.len())
                .unwrap_or(0) as isize,
        };
        let mut current_state = match self.selected {
            SelectedColumn::Function => &mut self.function_state,
            SelectedColumn::Hex | SelectedColumn::Disasm => &mut self.editor_state,
        };

        let next = (current_state.selected().unwrap_or(0) as isize + val).rem_euclid(len) as usize;

        current_state.select(Some(next));
    }
}
