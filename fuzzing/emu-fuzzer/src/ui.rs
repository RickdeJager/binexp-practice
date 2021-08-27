use std::io;
use std::time::Duration;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tui::Terminal;
use tui::backend::CrosstermBackend;
use tui::widgets::{Wrap, Block, Borders, Paragraph};
use tui::layout::{Layout, Constraint, Direction};

use crate::Stats;


/// Holds the data needed to render the ui, including some history for graphs.
struct UiData {
    /// How long are the VecDeques' tracking for?
    lookback: f64,

    /// Last stats, to calculate delta's with
    last_cases  : usize,
    last_inst   : usize,
}

impl UiData {
    /// Create a new UiData object, preloaded with `hist` items in each Deque.
    pub fn new(hist: usize) -> Self {
        UiData {
            lookback    : hist as f64,
            last_cases  : 0,
            last_inst   : 0,
        }
    }
}

pub struct Ui {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    stats   : Arc<Stats>,
    data    : UiData,
    interval: f64,
}

impl Ui {

    pub fn new(stats: Arc<Stats>, interval: f64) -> Option<Self> {
        let stdout = io::stdout();
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend).ok()?;
        terminal.clear().ok()?;

        let ui = Ui{
            terminal: terminal,
            stats   : stats,
            data    : UiData::new(10),
            interval: interval,
        };
        Some(ui)
    }

    /// Update the entire UI.
    /// 1. Fetch some stats from the shared stats object.
    /// 2. Update local data stores.
    /// 3. Render new ui based on local data.
    pub fn tick(&mut self, elapsed: Duration) -> Option<()> {
        let elapsed_f64  = elapsed.as_secs_f64();

        // Fetch the required data:
        let cases = self.stats.fuzz_cases.load(Ordering::SeqCst);
        let crashes = self.stats.crashes.load(Ordering::SeqCst);
        let inst = self.stats.instructions.load(Ordering::SeqCst);

        let cases_delta = (cases - self.data.last_cases) as f64;
        let inst_delta  = (inst - self.data.last_inst)   as f64;

        self.data.last_cases = cases;
        self.data.last_inst = inst;

        let history = self.data.lookback * self.interval;

        self.terminal.draw(|f| {
            let block = Block::default()
                .title("SEMU - The Slow Emulator. (Fuzz edition)")
                .borders(Borders::ALL);
            f.render_widget(block, f.size());

            let root = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Percentage(60),
                    Constraint::Percentage(40),
                ].as_ref())
                .split(f.size());


            ///////////////////////////////////////////////////
            //TEXT AND COUNTER SECTION/////////////////////////
            ///////////////////////////////////////////////////
            
            let top = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(50),
                    Constraint::Percentage(50),
                ].as_ref())
                .split(root[0]);

            // Stats block
            

            let stats_text = format!(
                "\n\
                Run time (sec)   : {:10.1?}\n\
                Total fuzz cases : {:10}\n\
                Total Crashes    : {:10}\n\
                 \n\
                Mill. inst / sec : {:10.2}\n\
                Fuzz cases / sec : {:10.0}\n\
                 \n\
                 \n\
                 \n\
                ",
                elapsed_f64,
                cases,
                crashes,
                (inst / 1_000_000) as f64 / elapsed_f64,
                cases as f64 / elapsed_f64,
                );
            let block = Paragraph::new(stats_text)
                .block(Block::default().title("Fuzzer stats").borders(Borders::ALL))
                .wrap(Wrap { trim: true });


            f.render_widget(block, top[0]);

            // Emulator block
            let block = Block::default()
                .title("Host stats")
                .borders(Borders::ALL);
            f.render_widget(block, top[1]);

        }).ok()?;

        Some(())
    }
}
