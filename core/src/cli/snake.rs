use std::collections::VecDeque;
use std::io::{self, Write};
use std::time::{Duration, Instant};

use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent},
    execute,
    style::{self, Stylize},
    terminal::{self, ClearType},
};
use rand::Rng;

const WIDTH: u16 = 40;
const HEIGHT: u16 = 20;
const TICK_MS: u64 = 100;

#[derive(Clone, Copy, PartialEq)]
enum Dir {
    Up,
    Down,
    Left,
    Right,
}

#[derive(Clone, Copy, PartialEq)]
struct Pos {
    x: u16,
    y: u16,
}

pub fn play() -> anyhow::Result<()> {
    let mut stdout = io::stdout();
    if terminal::enable_raw_mode().is_err() {
        println!("  Snake requires an interactive terminal.");
        return Ok(());
    }
    execute!(
        stdout,
        terminal::EnterAlternateScreen,
        cursor::Hide,
        terminal::Clear(ClearType::All)
    )?;

    let result = game_loop(&mut stdout);

    execute!(
        stdout,
        cursor::Show,
        terminal::LeaveAlternateScreen
    )?;
    terminal::disable_raw_mode()?;

    result
}

fn game_loop(stdout: &mut io::Stdout) -> anyhow::Result<()> {
    let mut rng = rand::thread_rng();

    // Initial snake in the middle
    let mut snake: VecDeque<Pos> = VecDeque::new();
    snake.push_back(Pos { x: WIDTH / 2, y: HEIGHT / 2 });
    snake.push_back(Pos { x: WIDTH / 2 - 1, y: HEIGHT / 2 });
    snake.push_back(Pos { x: WIDTH / 2 - 2, y: HEIGHT / 2 });

    let mut dir = Dir::Right;
    let mut next_dir = Dir::Right;
    let mut food = spawn_food(&snake, &mut rng);
    let mut score: u32 = 0;
    let mut game_over = false;

    // Draw initial frame
    draw(stdout, &snake, &food, score)?;

    loop {
        let tick_start = Instant::now();

        // Poll input
        while event::poll(Duration::from_millis(0))? {
            if let Event::Key(KeyEvent { code, .. }) = event::read()? {
                match code {
                    KeyCode::Up | KeyCode::Char('k') if dir != Dir::Down => {
                        next_dir = Dir::Up;
                    }
                    KeyCode::Down | KeyCode::Char('j') if dir != Dir::Up => {
                        next_dir = Dir::Down;
                    }
                    KeyCode::Left | KeyCode::Char('h') if dir != Dir::Right => {
                        next_dir = Dir::Left;
                    }
                    KeyCode::Right | KeyCode::Char('l') if dir != Dir::Left => {
                        next_dir = Dir::Right;
                    }
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('r') if game_over => {
                        // Restart
                        snake.clear();
                        snake.push_back(Pos { x: WIDTH / 2, y: HEIGHT / 2 });
                        snake.push_back(Pos { x: WIDTH / 2 - 1, y: HEIGHT / 2 });
                        snake.push_back(Pos { x: WIDTH / 2 - 2, y: HEIGHT / 2 });
                        dir = Dir::Right;
                        next_dir = Dir::Right;
                        food = spawn_food(&snake, &mut rng);
                        score = 0;
                        game_over = false;
                    }
                    _ => {}
                }
            }
        }

        if game_over {
            // Wait for input in game over state
            let elapsed = tick_start.elapsed();
            if elapsed < Duration::from_millis(TICK_MS) {
                std::thread::sleep(Duration::from_millis(TICK_MS) - elapsed);
            }
            continue;
        }

        dir = next_dir;

        // Move snake
        let head = snake.front().unwrap();
        let new_head = match dir {
            Dir::Up => Pos {
                x: head.x,
                y: head.y.wrapping_sub(1),
            },
            Dir::Down => Pos {
                x: head.x,
                y: head.y + 1,
            },
            Dir::Left => Pos {
                x: head.x.wrapping_sub(1),
                y: head.y,
            },
            Dir::Right => Pos {
                x: head.x + 1,
                y: head.y,
            },
        };

        // Check wall collision
        if new_head.x == 0 || new_head.x > WIDTH || new_head.y == 0 || new_head.y > HEIGHT {
            game_over = true;
            draw_game_over(stdout, score)?;
            continue;
        }

        // Check self collision
        if snake.iter().any(|p| *p == new_head) {
            game_over = true;
            draw_game_over(stdout, score)?;
            continue;
        }

        snake.push_front(new_head);

        // Check food
        if new_head == food {
            score += 10;
            food = spawn_food(&snake, &mut rng);
        } else {
            snake.pop_back();
        }

        draw(stdout, &snake, &food, score)?;

        // Tick rate
        let elapsed = tick_start.elapsed();
        if elapsed < Duration::from_millis(TICK_MS) {
            std::thread::sleep(Duration::from_millis(TICK_MS) - elapsed);
        }
    }
}

fn spawn_food(snake: &VecDeque<Pos>, rng: &mut impl Rng) -> Pos {
    loop {
        let pos = Pos {
            x: rng.gen_range(1..=WIDTH),
            y: rng.gen_range(1..=HEIGHT),
        };
        if !snake.iter().any(|p| *p == pos) {
            return pos;
        }
    }
}

fn draw(stdout: &mut io::Stdout, snake: &VecDeque<Pos>, food: &Pos, score: u32) -> anyhow::Result<()> {
    execute!(stdout, cursor::MoveTo(0, 0))?;

    // Top border
    let header = format!(" TORCHSIGHT SNAKE    Score: {:<6}  [q] quit ", score);
    let pad = (WIDTH as usize + 2).saturating_sub(header.len());
    write!(
        stdout,
        "{}{}",
        style::style(&header).cyan().bold(),
        " ".repeat(pad)
    )?;
    write!(stdout, "\r\n")?;

    let top: String = format!("┌{}┐", "─".repeat(WIDTH as usize));
    write!(stdout, "{}\r\n", style::style(&top).dark_grey())?;

    for y in 1..=HEIGHT {
        write!(stdout, "{}", style::style("│").dark_grey())?;
        for x in 1..=WIDTH {
            let pos = Pos { x, y };
            if snake.front() == Some(&pos) {
                write!(stdout, "{}", style::style("@").green().bold())?;
            } else if snake.iter().any(|p| *p == pos) {
                write!(stdout, "{}", style::style("o").green())?;
            } else if *food == pos {
                write!(stdout, "{}", style::style("*").red().bold())?;
            } else {
                write!(stdout, " ")?;
            }
        }
        write!(stdout, "{}\r\n", style::style("│").dark_grey())?;
    }

    let bottom: String = format!("└{}┘", "─".repeat(WIDTH as usize));
    write!(stdout, "{}\r\n", style::style(&bottom).dark_grey())?;

    write!(
        stdout,
        "{}",
        style::style(" arrows/hjkl: move  q: quit").dark_grey()
    )?;

    stdout.flush()?;
    Ok(())
}

fn draw_game_over(stdout: &mut io::Stdout, score: u32) -> anyhow::Result<()> {
    let cx = WIDTH / 2 - 6;
    let cy = HEIGHT / 2;

    execute!(stdout, cursor::MoveTo(cx + 1, cy))?;
    write!(stdout, "{}", style::style("  GAME  OVER  ").red().bold())?;

    execute!(stdout, cursor::MoveTo(cx, cy + 1))?;
    write!(
        stdout,
        "{}",
        style::style(format!("  Score: {:<6} ", score)).yellow()
    )?;

    execute!(stdout, cursor::MoveTo(cx, cy + 2))?;
    write!(
        stdout,
        "{}",
        style::style(" [r] retry [q] quit").dark_grey()
    )?;

    stdout.flush()?;
    Ok(())
}
