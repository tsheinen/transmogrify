mod application;
mod event;
mod util;

use crate::event::{Event, Events};
use crate::util::{Mode, Column, Function};

use crate::application::Application;
use r2pipe::{open_pipe, R2Pipe};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::io;
use std::path::PathBuf;
use structopt::StructOpt;
use termion::event::Key;
use termion::input::MouseTerminal;
use termion::raw::IntoRawMode;
use termion::screen::AlternateScreen;
use tui::backend::TermionBackend;
use tui::layout::{Alignment, Constraint, Direction, Layout};
use tui::style::{Color, Modifier, Style};
use tui::text::Spans;
use tui::widgets::{Block, Borders, List, ListItem, Paragraph};
use tui::Terminal;

#[derive(StructOpt, Debug)]
#[structopt(about, author)]
struct Opt {
    #[structopt(name = "FILE", parse(from_os_str))]
    file: PathBuf,
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
    // using r2 so we can pull functions from stripped binaries -- is there a better way to do this?
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
    let opt = Opt::from_args();

    // Terminal initialization
    let stdout = io::stdout().into_raw_mode()?;
    let stdout = MouseTerminal::from(stdout);
    let stdout = AlternateScreen::from(stdout);
    let backend = TermionBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let events = Events::new();

    // App

    let mut app = Application::new(opt.file.to_string_lossy());
    app.editor_state.select(Some(0));
    app.function_state.select(Some(0));

    loop {
        terminal.draw(|f| {
            // this solves for the correct proportions of the bar/main in a responsive way
            let (main_size, bar_size) = {
                let (_, rows) = termion::terminal_size().unwrap_or((0, 0));
                let (_, rows_px) = termion::terminal_size_pixels().unwrap_or((0, 0));
                let rows_px = rows_px as f32;
                let rows = rows as f32;
                let bar_size = 1f32 * (rows_px / rows) as f32;
                (
                    ((rows_px - bar_size) / rows_px * 100f32) as u16,
                    (bar_size / rows_px * 100f32) as u16,
                )
            };

            let (functions, hex, disasm_view, _bar) = {
                let vchunks = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(0)
                    .constraints(
                        [
                            Constraint::Percentage(main_size),
                            Constraint::Percentage(bar_size),
                        ]
                        .as_ref(),
                    )
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
                f.render_stateful_widget(
                    make_list(
                        app.get_functions(""),
                        "Functions",
                        app.selected == Column::Function,
                    ),
                    functions,
                    &mut app.function_state,
                );
            }

            let func = app.get_current_function();

            match app.selected {
                Column::Hex => {
                    f.set_cursor(
                        hex.x + app.get_cursor() as u16 + 1 + (app.mode == Mode::Editing) as u16,
                        hex.y + 1u16 + app.editor_state.selected().unwrap_or(0) as u16,
                    );
                }
                Column::Disasm => {
                    f.set_cursor(
                        disasm_view.x
                            + app.get_cursor() as u16
                            + 1
                            + (app.mode == Mode::Editing) as u16,
                        disasm_view.y + 1u16 + app.editor_state.selected().unwrap_or(0) as u16,
                    );
                }
                _ => {}
            }

            {
                let hex_bytes = app.bytes.get(&func.name).unwrap().clone();

                f.render_widget(
                    make_list(hex_bytes, "Hex", app.selected == Column::Hex),
                    hex,
                );
            }

            {
                let disasm = app.disasm.get(&func.name).unwrap().clone();

                f.render_widget(
                    make_list(disasm, "Disasm", app.selected == Column::Disasm),
                    disasm_view,
                );
            }

            let paragraph = Paragraph::new(app.get_bar())
                .style(Style::default().fg(Color::White))
                .block(Block::default().borders(Borders::NONE));
            f.render_widget(paragraph, _bar);
        })?;

        match events.next()? {
            Event::Input(input) => {
                // handle mode specific operations
                match app.mode {
                    Mode::Viewing => match input {
                        Key::Char('q') => {
                            break;
                        }
                        Key::Char('w') => {
                            app.write();
                        }
                        Key::Char('a') => app.select(Column::Function),
                        Key::Char('s') => app.select(Column::Hex),
                        Key::Char('d') => app.select(Column::Disasm),
                        Key::Char('e') if app.selected != Column::Function => {
                            app.mode = Mode::Editing
                        }
                        _ => {}
                    },
                    Mode::Editing => match input {
                        Key::Esc => {
                            app.mode = Mode::Viewing;
                        }
                        Key::Char(_) | Key::Delete | Key::Backspace | Key::Home | Key::End => {
                            app.apply_key(input)
                        }
                        _ => {}
                    },
                }

                // handle cursor movement or list select state
                match app.selected {
                    Column::Function => match input {
                        Key::Down => {
                            app.next_column();
                            app.editor_state.select(Some(0));
                        }
                        Key::Up => {
                            app.previous_column();
                            app.editor_state.select(Some(0));
                        }
                        _ => {}
                    },
                    Column::Hex | Column::Disasm => match input {
                        Key::Down => {
                            app.next_column();
                        }
                        Key::Up => {
                            app.previous_column();
                        }
                        Key::Left => app.set_cursor(app.get_cursor() - 1),
                        Key::Right => app.set_cursor(app.get_cursor() + 1),
                        Key::Home => app.set_cursor(0),
                        Key::End => {
                            let len = app
                                .get(
                                    app.get_current_function().clone().name,
                                    app.editor_state.selected().unwrap_or(0),
                                )
                                .map(|x| match app.selected {
                                    Column::Disasm => x.1.len(),
                                    Column::Hex => x.0.len(),
                                    _ => 0,
                                })
                                .unwrap_or(0) as isize;
                            app.set_cursor(len - 1)
                        }
                        _ => {}
                    },
                }
            }

            Event::Tick => {
                let editable = app.selected.editable();
                if editable {
                    app.rebuild();
                }
            }
        }
    }

    Ok(())
}

fn make_list(items: impl IntoIterator<Item = String>, title: &str, selected: bool) -> List {
    List::new(
        items
            .into_iter()
            .map(|i| {
                let lines = vec![Spans::from(i)];
                ListItem::new(lines).style(Style::default().fg(Color::White))
            })
            .collect::<Vec<_>>(),
    )
    .block(if selected {
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(Color::LightGreen))
    } else {
        Block::default().borders(Borders::ALL).title(title)
    })
    .highlight_style(
        Style::default()
            .bg(Color::LightGreen)
            .fg(Color::Black)
            .add_modifier(Modifier::BOLD),
    )
}
