//! The activity readout's animation: a stock shimmer dressing the scan under way.

use std::hash::{BuildHasher, RandomState};
use std::time::{Duration, Instant};

use color_eyre::eyre::{Result, eyre};
use libshimmer::{Glyphs, Intensity, Recipe, Shimmer, Spell, Wide, stock};

use super::app::App;

/// The glyph repertoires memview assumes: none beyond the base set, since it cannot tell which
/// glyphs its terminal draws.
const GLYPHS: Glyphs = Glyphs::BASE;

/// How long a scan runs before the readout shows it, so that quick refreshes do not flicker.
const NOTICE: Duration = Duration::from_millis(300);

/// A scan under way, as the activity readout names it.
struct Scan {
    caption: String,
    started: Instant,
}

impl Scan {
    /// The scan the readout shows at `now`: the selected process's mappings, else the shared
    /// ledger, else the process scan the current tab drives, once it has run for [`NOTICE`].
    fn of(app: &App, now: Instant) -> Option<Self> {
        Self::under_way(app).filter(|scan| now.saturating_duration_since(scan.started) >= NOTICE)
    }

    fn under_way(app: &App) -> Option<Self> {
        if let Some((pid, started)) = app.process_mapping_started_at() {
            return Some(Self {
                caption: format!("Reading mappings of {pid}"),
                started,
            });
        }
        if let Some(started) = app.shared_scan_started_at() {
            return Some(Self {
                caption: "Building the shared ledger".to_owned(),
                started,
            });
        }
        app.process_scan_started_at
            .filter(|_| app.tab.drives_process_scans())
            .map(|started| Self {
                caption: "Scanning processes".to_owned(),
                started,
            })
    }
}

/// The shimmer that dresses each scan, on the clock of the frames that draw it.
pub struct Activity {
    shimmer: Shimmer,
    /// When the shimmer last advanced.
    advanced: Instant,
}

impl Activity {
    /// A shimmer of a random stock recipe that the base glyphs draw. memview scans as fast as it
    /// can, so it works briskly whenever a scan runs.
    pub fn summon(now: Instant) -> Result<Self> {
        let seed = RandomState::new().hash_one(());
        let fitting: Vec<&'static Recipe> = stock::ROSTER
            .iter()
            .filter(|recipe| recipe.fits::<Wide>(GLYPHS).is_ok())
            .collect();
        let recipe = seed
            .checked_rem(u64::try_from(fitting.len())?)
            .and_then(|pick| fitting.get(usize::try_from(pick).ok()?))
            .ok_or_else(|| eyre!("no stock shimmer draws with the base glyphs"))?;
        let mut shimmer = Shimmer::new(recipe, seed, GLYPHS)?;
        shimmer.set_intensity(Intensity::BRISK);
        Ok(Self {
            shimmer,
            advanced: now,
        })
    }

    /// Follows `app` up to `now`: busy, under the scan's caption, while the readout shows a scan;
    /// idle otherwise.
    pub fn follow(&mut self, app: &App, now: Instant) {
        match Scan::of(app, now) {
            Some(scan) => {
                self.shimmer.show(&scan.caption);
                self.shimmer.set_spell(Spell::Busy);
            }
            None => self.shimmer.set_spell(Spell::Idle),
        }
        self.shimmer
            .advance(now.saturating_duration_since(self.advanced));
        self.advanced = now;
    }

    pub fn shimmer(&self) -> &Shimmer {
        &self.shimmer
    }

    /// How long the scan the readout shows has run, as of the frame the shimmer last followed;
    /// none while the readout shows no scan.
    pub fn running(&self, app: &App) -> Option<Duration> {
        Scan::of(app, self.advanced)
            .map(|scan| self.advanced.saturating_duration_since(scan.started))
    }
}
