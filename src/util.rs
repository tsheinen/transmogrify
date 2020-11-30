use crate::{get_functions, Function};
use capstone::prelude::*;
use capstone::{Capstone, Insn};
use std::collections::HashMap;
use tui::widgets::ListState;
use r2pipe::{open_pipe, R2Pipe};


pub enum SelectedColumn {
    Function,
    Hex,
    Disasm
}

impl SelectedColumn {
    pub fn to_i8(&self) -> i8 {
        match self {
            Self::Function => 0,
            Self::Hex => 1,
            Self::Disasm => 2,
        }
    }

    pub fn from_i8(val: i8) -> SelectedColumn {
        match ((val % 3) + 3) % 3 {
            0 => Self::Function,
            1 => Self::Hex,
            2 => Self::Disasm,
            _ => unreachable!()
        }
    }
}

pub fn disasm(bytes: &[u8]) -> Vec<(Vec<u8>, String)> {
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Att)
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
    pub bytes: HashMap<String, Vec<Vec<u8>>>,
    pub disasm: HashMap<String, Vec<String>>,
    pub function_state: ListState,
    pub editor_state: ListState,
    pub selected: SelectedColumn
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

        let (bytes, disasm): (Vec<(String, Vec<Vec<u8>>)>, Vec<(String, Vec<String>)>) = functions
            .iter()
            .map(|function| {
                let (bytes, disasm): (Vec<Vec<u8>>, Vec<String>) =
                    disasm(&program[function.offset..function.offset + function.size])
                        .into_iter()
                        .unzip();
                (
                    (function.name.clone(), bytes),
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
            selected: SelectedColumn::Function
        }
    }

    pub fn get(&self, function: String, i: usize) -> Option<(&Vec<u8>, &String)> {
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
            bytes_data[i] = bytes.clone();
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
            bytes[i] = asm(data.clone()).expect("asm to work");
            disasm[i] = data;
            Ok(())
        } else {
            Err(format!("i outside of range"))
        }
    }

    pub fn values(&self, function: String) -> impl Iterator<Item = (Vec<u8>, String)> {
        let bytes = self.bytes.get(&function).cloned().unwrap_or(vec![]);
        let disasm = self.disasm.get(&function).cloned().unwrap_or(vec![]);
        bytes.into_iter().zip(disasm.into_iter())
    }

    pub fn get_current_function(&self) -> &Function {
        &self.functions[self.function_state.selected().unwrap_or(0)]
    }


    pub fn next(&mut self) {
        let current_func_name = self.get_current_function().name.clone();

        let mut current_state = match self.selected {
            SelectedColumn::Function => &mut self.function_state,
            SelectedColumn::Hex | SelectedColumn::Disasm => &mut self.editor_state
        };

        let i = match current_state.selected() {
            Some(i) => {
                if i >= self.bytes.get(&current_func_name).map(|x| x.len()).unwrap_or(0) - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        current_state.select(Some(i));
    }

    pub fn previous(&mut self) {
        let current_func_name = self.get_current_function().name.clone();
        let mut current_state = match self.selected {
            SelectedColumn::Function => &mut (self.function_state),
            SelectedColumn::Hex | SelectedColumn::Disasm => &mut (self.editor_state)
        };

        let i = match current_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.bytes.get(&current_func_name).map(|x| x.len()).unwrap_or(0) - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        current_state.select(Some(i));
    }



    pub fn next_col(&mut self) {
        self.selected = SelectedColumn::from_i8(self.selected.to_i8() + 1)
    }

    pub fn previous_col(&mut self) {
        self.selected = SelectedColumn::from_i8(self.selected.to_i8() - 1)

    }


    // pub fn unselect_function(&mut self) {
    //     self.function_state.select(None);
    // }

}
