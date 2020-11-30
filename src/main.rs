mod event;
mod util;

use crate::event::{Event, Events};
use crate::util::{Application, Mode, SelectedColumn};
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

    let mut app = Application::new(program_name);
    app.editor_state.select(Some(0));
    app.function_state.select(Some(0));

    loop {
        terminal.draw(|f| {
            let (functions, hex, disasm_view, bar) = {
                let vchunks = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(0)
                    .constraints([Constraint::Percentage(95), Constraint::Percentage(5)].as_ref())
                    .split(f.size());
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
                    .split(vchunks[0]);
                (chunks[0], chunks[1], chunks[2], vchunks[1])
            };
            app.column_width = hex.width as isize;
            {
                let items: Vec<ListItem> = app
                    .functions
                    .iter()
                    .map(|i| {
                        let mut lines = vec![Spans::from(i.name.as_ref())];
                        ListItem::new(lines).style(Style::default().fg(Color::White))
                    })
                    .collect();
                let items = List::new(items)
                    .block(Block::default().borders(Borders::ALL).title("Functions"))
                    .highlight_style(
                        Style::default()
                            .bg(Color::LightGreen)
                            .fg(Color::Black)
                            .add_modifier(Modifier::BOLD),
                    );
                f.render_stateful_widget(items, functions, &mut app.function_state);
            }

            let func = app.get_current_function();

            match app.selected {
                SelectedColumn::Hex => {
                    f.set_cursor(
                        hex.x + app.cursor_index as u16 + 1,
                        hex.y + 1u16 + app.editor_state.selected().unwrap_or(0) as u16,
                    );
                }
                SelectedColumn::Disasm => {
                    f.set_cursor(
                        disasm_view.x + app.cursor_index as u16 + 1,
                        disasm_view.y + 1u16 + app.editor_state.selected().unwrap_or(0) as u16,
                    );
                }
                _ => {}
            }

            {
                let hex_bytes = app
                    .bytes
                    .get(&func.name)
                    .unwrap();
                    // .iter()
                    // .map(|x| {
                    //     x.iter()
                    //         .map(|y| format!("{:x}", y))
                    //         .collect::<Vec<_>>()
                    //         .join(" ")
                    // })
                    // .collect::<Vec<_>>();
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
                    );
                f.render_widget(items, hex);
            }

            {
                let disasm = app.disasm.get(&func.name).unwrap();
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
                f.render_widget(items, disasm_view);
            }

        })?;

        match events.next()? {
            Event::Input(input) => match app.mode {
                Mode::Viewing => match input {
                    Key::Char('q') => {
                        break;
                    }
                    Key::Char('a') => app.selected = SelectedColumn::Function,
                    Key::Char('s') => app.selected = SelectedColumn::Hex,
                    Key::Char('d') => app.selected = SelectedColumn::Disasm,
                    Key::Char('e') => app.mode = Mode::Editing,
                    _ => match app.selected {
                        SelectedColumn::Function => match input {
                            Key::Down => {
                                app.next();
                                app.editor_state.select(Some(0));
                            }
                            Key::Up => {
                                app.previous();
                                app.editor_state.select(Some(0));
                            }
                            _ => {}
                        },
                        SelectedColumn::Hex | SelectedColumn::Disasm => match input {
                            Key::Down => {
                                app.next();
                            }
                            Key::Up => {
                                app.previous();
                            }
                            _ => {}
                        },
                        _ => {}
                    },
                },
                Mode::Editing => match input {
                    Key::Esc => app.mode = Mode::Viewing,
                    _ if app.selected.editable() => match input {
                        Key::Left => {
                            let len = app.column_width;
                            app.cursor_index = (((app.cursor_index - 1) % len) + len) % len;
                        }
                        Key::Right => {
                            let len = app.column_width;
                            app.cursor_index = (((app.cursor_index + 1) % len) + len) % len;
                        }
                        _ => {}
                    },
                    _ => {}
                },
            },

            Event::Tick => {}
        }
    }

    Ok(())
}
