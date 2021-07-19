use std::io;
use std::time::Duration;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::collections::vec_deque::VecDeque;

use tui::Terminal;
use tui::backend::CrosstermBackend;
use tui::style::{Style, Color};
use tui::widgets::{Wrap, Block, Borders, Paragraph, Chart, Dataset, Axis};
use tui::layout::{Layout, Constraint, Direction};

use crate::Stats;


/// Holds the data needed to render the ui, including some history for graphs.
struct UiData {
    /// How long are the VecDeques' tracking for?
    lookback: f64,

    /// Stats and stuff.
    fuzz_cases: VecDeque<(f64, f64)>,
    crashes: VecDeque<(f64, f64)>,
    instructions: VecDeque<(f64, f64)>,
}

impl UiData {
    /// Create a new UiData object, preloaded with `hist` items in each Deque.
    pub fn new(hist: usize) -> Self {
        UiData {
            lookback: hist as f64,
            fuzz_cases  : vec![(0f64, 0f64); hist].into_iter().collect(),
            crashes     : vec![(0f64, 0f64); hist].into_iter().collect(),
            instructions: vec![(0f64, 0f64); hist].into_iter().collect(),
        }
    }
}

pub struct Ui {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    stats   : Arc<Stats>,
    data    : UiData,
}

impl Ui {

    pub fn new(stats: Arc<Stats>) -> Option<Self> {
        let stdout = io::stdout();
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend).ok()?;
        terminal.clear().ok()?;

        let ui = Ui{
            terminal: terminal,
            stats   : stats,
            data    : UiData::new(100),
        };
        Some(ui)
    }

    /// Update the entire UI.
    /// 1. Fetch some stats from the shared stats object.
    /// 2. Update local data stores.
    /// 3. Render new ui based on local data.
    pub fn tick(&mut self, elapsed: Duration) -> Option<()> {
        let elapsed_f64 = elapsed.as_secs_f64();

        // Fetch the required data:
        let cases = self.stats.fuzz_cases.load(Ordering::SeqCst);
        let crashes = self.stats.crashes.load(Ordering::SeqCst);
        let inst = self.stats.instructions.load(Ordering::SeqCst);

        let cases_delta = cases as f64 - self.data.fuzz_cases[0].1;
        let inst_delta  = inst as f64 - self.data.instructions[0].1;

        // Push the new data into the queue
        self.data.fuzz_cases.push_front((elapsed_f64, cases_delta));
//        self.data.fuzz_cases.push_front((elapsed_f64, 3.5f64));
        self.data.crashes.push_front((elapsed_f64, crashes as f64));
        self.data.instructions.push_front((elapsed_f64, inst_delta));

        // Remove one old entry from each queue
        self.data.fuzz_cases.pop_back();
        self.data.crashes.pop_back();
        self.data.instructions.pop_back();


        self.data.fuzz_cases.make_contiguous();
        let data_fuzz_cases = Dataset::default()
            .data(self.data.fuzz_cases.as_slices().0);

        self.data.instructions.make_contiguous();
        let data_instructions = Dataset::default()
            .data(self.data.instructions.as_slices().0);

        let hist = self.data.lookback;


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
                ",
               // (&self).data.fuzz_cases[0],
               // (&self).data.crashes[0],
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


            ///////////////////////////////////////////////////
            //GRAPH SECTION////////////////////////////////////
            ///////////////////////////////////////////////////

            let graphs = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(33),
                    Constraint::Percentage(34),
                    Constraint::Percentage(33),
                ].as_ref())
                .split(root[1]);

            /*
            // Add a coverage graph
            let block = Block::default()
                .title("Coverage")
                .borders(Borders::ALL);
            f.render_widget(block, graphs[0]);*/
        

            let fcps = Chart::new(vec![data_fuzz_cases])
                .block(Block::default()
                       .title("Fuzz cases / jiffie")
                       .borders(Borders::ALL))
                .x_axis(Axis::default()
                    .title("Time")
                    .title_style(Style::default().fg(Color::Red))
                    .style(Style::default().fg(Color::Gray))
                    .bounds([elapsed_f64-3f64, elapsed_f64])
 //                   .labels(&["0.0", "5.0", "10.0"])
                   )
                .y_axis(Axis::default()
                    .title("Y Axis")
                    .title_style(Style::default().fg(Color::Red))
                    .style(Style::default().fg(Color::Gray))
                    .bounds([0.75f64 * cases_delta, 1.5f64 * cases_delta])
//                    .labels(&["0.0", "5.0", "10.0"])
                    );

            f.render_widget(fcps, graphs[0]);



            let mips = Chart::new(vec![data_instructions])
                .block(Block::default()
                       .title("Million Instructions / sec")
                       .borders(Borders::ALL))
                .x_axis(Axis::default()
                    .title("Time")
                    .title_style(Style::default().fg(Color::Red))
                    .style(Style::default().fg(Color::Gray))
                    .bounds([elapsed_f64-3f64, elapsed_f64])
 //                   .labels(&["0.0", "5.0", "10.0"])
                   )
                .y_axis(Axis::default()
                    .title("Y Axis")
                    .title_style(Style::default().fg(Color::Red))
                    .style(Style::default().fg(Color::Gray))
                    .bounds([0.9f64 * inst_delta, 1.1f64 * inst_delta])
//                    .labels(&["0.0", "5.0", "10.0"])
                    );

            f.render_widget(mips, graphs[1]);


            
            // Add a crashes graph
            let block = Block::default()
                .title("Crashes")
                .borders(Borders::ALL);
            f.render_widget(block, graphs[2]);




        }).ok()?;

        Some(())
    }
}
