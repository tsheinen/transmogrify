mod event;
mod util;

use crate::event::{Event, Events};
use crate::util::{Application, StatefulList};
use capstone::prelude::*;
use capstone::Capstone;
use r2pipe::{open_pipe, R2Pipe};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::io;
use std::path::Path;
use termion::event::Key;
use termion::input::MouseTerminal;
use termion::raw::IntoRawMode;
use termion::screen::AlternateScreen;
use tui::backend::TermionBackend;
use tui::layout::{Constraint, Direction, Layout};
use tui::style::{Color, Modifier, Style};
use tui::text::{Span, Spans};
use tui::widgets::{Block, Borders, List, ListItem, ListState};
use tui::Terminal;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Function {
    name: String,
    offset: usize,
    size: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct FunctionDisassembly {
    name: String,
    ops: Vec<Instruction>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Instruction {
    bytes: String,
    disasm: String,
}

fn get_functions<P: AsRef<str>>(program: P) -> Vec<Function> {
    /// using r2 so we can pull functions from stripped binaries -- is there a better way to do this?
    let mut r2p = open_pipe!(Some(program)).unwrap();
    r2p.cmd("aaa").unwrap();
    let x = r2p.cmd("aflj").unwrap();
    if let Ok(json) = serde_json::from_str::<Vec<Function>>(&x) {
        json
    } else {
        vec![]
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let program_name = "./a.out";

    let program = std::fs::read(program_name).unwrap();


    let functions = get_functions(program_name);

    let function_names = functions.iter().map(|x| x.name.clone()).collect::<Vec<_>>();

    // Terminal initialization
    let stdout = io::stdout().into_raw_mode()?;
    let stdout = MouseTerminal::from(stdout);
    let stdout = AlternateScreen::from(stdout);
    let backend = TermionBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let events = Events::new();

    // App

    let byte_list = Application::new(program_name);

    let mut function_list_state = StatefulList::with_items(function_names);

    loop {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints(
                    [
                        Constraint::Percentage(33),
                        Constraint::Percentage(33),
                        Constraint::Percentage(33),
                    ]
                    .as_ref(),
                )
                .split(f.size());

            {
                let items: Vec<ListItem> = function_list_state
                    .items
                    .iter()
                    .map(|i| {
                        let mut lines = vec![Spans::from(i.as_ref())];
                        ListItem::new(lines).style(Style::default().fg(Color::White))
                    })
                    .collect();
                let items = List::new(items)
                    .block(Block::default().borders(Borders::ALL).title("Functions"))
                    .highlight_style(
                        Style::default()
                            .bg(Color::LightGreen)
                            .add_modifier(Modifier::BOLD),
                    )
                    .highlight_symbol(">> ");
                f.render_stateful_widget(items, chunks[0], &mut function_list_state.state);
            }

            let func = functions[function_list_state.state.selected().unwrap_or(0)].clone();

            {

                let hex_bytes = byte_list
                    .bytes
                    .get(&func.name)
                    .unwrap()
                    .iter()
                    .map(|x| {
                        x.iter()
                            .map(|y| format!("{:x}", y))
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                    .collect::<Vec<_>>();
                let items: Vec<ListItem> = hex_bytes
                    .iter()
                    .map(|i| {
                        let mut lines = vec![Spans::from(i.as_ref())];
                        ListItem::new(lines).style(Style::default().fg(Color::White))
                    })
                    .collect();
                let items = List::new(items)
                    .block(Block::default().borders(Borders::ALL).title("Hex"))
                    .highlight_style(
                        Style::default()
                            .bg(Color::LightGreen)
                            .add_modifier(Modifier::BOLD),
                    )
                    .highlight_symbol(">> ");
                f.render_widget(items, chunks[1]);
            }

            {
                let disasm = byte_list.disasm.get(&func.name).unwrap();
                let items: Vec<ListItem> = disasm
                    .iter()
                    .map(|i| {
                        let mut lines = vec![Spans::from(i.as_ref())];
                        ListItem::new(lines).style(Style::default().fg(Color::White))
                    })
                    .collect();
                let items = List::new(items)
                    .block(Block::default().borders(Borders::ALL).title("Disasm"))
                    .highlight_style(
                        Style::default()
                            .bg(Color::LightGreen)
                            .add_modifier(Modifier::BOLD),
                    );
                f.render_widget(items, chunks[2]);
            }
        })?;

        match events.next()? {
            Event::Input(input) => match input {
                Key::Char('q') => {
                    break;
                }
                Key::Left => {
                    function_list_state.unselect();
                }
                Key::Down => {
                    function_list_state.next();
                }
                Key::Up => {
                    function_list_state.previous();
                }
                _ => {}
            },

            Event::Tick => {}
        }
    }

    Ok(())
}
