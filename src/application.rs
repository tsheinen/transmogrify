use crate::util::{from_hexstring, Mode, SelectedColumn};
use crate::{util, Function};
use core::option::Option::{None, Some};
use core::result::Result::Ok;
use r2pipe::{open_pipe, R2Pipe};
use std::collections::HashMap;
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
use termion::event::Key;
use tui::widgets::ListState;

pub struct Application {
    pub file: PathBuf,
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
        let functions = serde_json::from_str::<Vec<Function>>(&x).unwrap_or_else(|_| vec![]);

        let program = std::fs::read(path.as_ref()).unwrap();

        type InstructionPair = (String, Vec<String>);

        let (bytes, disasm): (Vec<InstructionPair>, Vec<InstructionPair>) = functions
            .iter()
            .map(|function| {
                let (bytes, disasm): (Vec<Vec<u8>>, Vec<String>) =
                    util::disassemble(&program[function.offset..function.offset + function.size])
                        .into_iter()
                        .unzip();
                (
                    (
                        function.name.clone(),
                        bytes.iter().map(|x| util::to_hexstring(x)).collect(),
                    ),
                    (function.name.clone(), disasm),
                )
            })
            .unzip();

        Application {
            file: PathBuf::from(path.as_ref()),
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

    pub fn rebuild_asm(&mut self) {
        let function = self.get_current_function().name.clone();

        let bytes = self
            .bytes
            .get_mut(&function)
            .expect("current function doesn't exist in map?");
        let disasm_vec = self
            .disasm
            .get_mut(&function)
            .expect("current function doesn't exist in map?");
        for i in 0..bytes.len() {
            disasm_vec[i] = util::disassemble(&util::from_hexstring(&bytes[i]))
                .first()
                .map(|x| x.1.clone())
                .unwrap_or_else(|| "INVALID".to_string());
        }
    }

    pub fn rebuild_bytes(&mut self) {
        let function = self.get_current_function().name.clone();

        let bytes = self
            .bytes
            .get_mut(&function)
            .expect("current function doesn't exist in map?");
        let disasm = self
            .disasm
            .get_mut(&function)
            .expect("current function doesn't exist in map?");
        for i in 0..bytes.len() {
            // TODO if the assembly is invalid we should handle that.  prob leave it alone?
            bytes[i] = util::to_hexstring(&util::assemble(disasm[i].clone()).expect("asm to work"));
        }
    }

    pub fn values(&self, function: String) -> impl Iterator<Item = (String, String)> {
        let bytes = self.bytes.get(&function).cloned().unwrap_or_else(|| vec![]);
        let disasm = self
            .disasm
            .get(&function)
            .cloned()
            .unwrap_or_else(|| vec![]);
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
        let current_state = match self.selected {
            SelectedColumn::Function => &mut self.function_state,
            SelectedColumn::Hex | SelectedColumn::Disasm => &mut self.editor_state,
        };

        let next = (current_state.selected().unwrap_or(0) as isize + val).rem_euclid(len) as usize;

        current_state.select(Some(next));
    }

    pub fn apply_key(&mut self, key: Key) {
        let current_func_name = self.get_current_function().name.clone();

        let current_state = match self.selected {
            SelectedColumn::Function => &mut self.function_state,
            SelectedColumn::Hex | SelectedColumn::Disasm => &mut self.editor_state,
        }
        .selected()
        .unwrap_or(0);

        let mut empty: Vec<String> = vec![];

        let current_str = match self.selected {
            SelectedColumn::Hex => {
                &mut self.bytes.get_mut(&current_func_name).unwrap_or(&mut empty)[current_state]
            }
            SelectedColumn::Disasm => &mut self
                .disasm
                .get_mut(&current_func_name)
                .unwrap_or(&mut empty)[current_state],
            _ => panic!(
                "trying to edit on a col which should never happen, means my logic is broken"
            ),
        };

        match key {
            Key::Char(c) => {
                current_str.insert(self.cursor_index as usize, c);
                self.cursor_index += 1;
            }
            Key::Delete => {
                current_str.remove(self.cursor_index as usize);
            }
            Key::Backspace if self.cursor_index > 0 => {
                current_str.remove(self.cursor_index as usize - 1);
                self.cursor_index -= 1;
            }
            _ => {}
        };
    }

    pub fn rebuild(&mut self) {
        match self.selected {
            SelectedColumn::Hex => {
                self.rebuild_asm();
            }
            SelectedColumn::Disasm => {
                self.rebuild_bytes();
            }
            SelectedColumn::Function => {
                panic!("should never call rebuild when current column is function");
            }
        }
    }

    pub fn write(&self) -> Result<(), std::io::Error> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(self.file.as_path())?;
        for function in &self.functions {
            file.seek(SeekFrom::Start(function.offset as u64));
            file.write(&self.bytes
                .get(&function.name)
                .map(|x| x.clone())
                .unwrap_or_else(|| vec![])
                .iter()
                .map(|x| from_hexstring(x))
                .map(|x| x.into_iter())
                .flatten()
                .collect::<Vec<u8>>());
        }
        Ok(())
    }


}

