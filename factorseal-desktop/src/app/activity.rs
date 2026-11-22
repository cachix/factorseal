//! Which app read which secret on this device, newest first.
use super::*;
use factorseal::{AccessOutcome, AccessRecord, AccessRequester};
use jiff::{Timestamp, Zoned, tz::TimeZone};

const RECENT_ON_ITEM: usize = 5;
const ACTIVITY_REFRESH: std::time::Duration = std::time::Duration::from_secs(3);

pub(super) fn application_name(path: &std::path::Path) -> String {
    path.file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned()
}

fn hidden_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{00AD}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061C}'
                | '\u{06DD}'
                | '\u{070F}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08E2}'
                | '\u{115F}'..='\u{1160}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{206F}'
                | '\u{3164}'
                | '\u{FEFF}'
                | '\u{FFA0}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{110BD}'
                | '\u{110CD}'
                | '\u{13430}'..='\u{1343F}'
                | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D173}'..='\u{1D17A}'
                | '\u{E0000}'..='\u{E007F}'
        )
}

pub(super) fn visible_text(text: &str) -> String {
    let visible: String = text
        .chars()
        .filter_map(|character| {
            if character.is_whitespace() {
                Some(' ')
            } else {
                (!hidden_character(character)).then_some(character)
            }
        })
        .collect();
    visible.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn website_host(origin: &str) -> &str {
    origin
        .split_once("://")
        .map_or(origin, |(_, host)| host)
        .trim_end_matches('/')
}

fn is_secret_spec(scope: factorseal::DocumentKind) -> bool {
    matches!(
        scope,
        factorseal::DocumentKind::SecretSpecProject
            | factorseal::DocumentKind::SecretSpecProviderCache
    )
}

fn requester_name(record: &AccessRecord) -> String {
    let name = match &record.requester {
        AccessRequester::Program { .. }
            if record.scope == factorseal::DocumentKind::NetworkManagerWifi =>
        {
            "NetworkManager".to_owned()
        }
        AccessRequester::Program { .. } if is_secret_spec(record.scope) => "SecretSpec".to_owned(),
        AccessRequester::Program { principal, .. } => {
            application_name(std::path::Path::new(&principal.application_id))
        }
        AccessRequester::Browser { origin } | AccessRequester::Website { origin } => {
            website_host(origin).to_owned()
        }
        AccessRequester::App { package } => package.clone(),
    };
    visible_text(&name)
}

fn record_entry<'a>(
    record: &AccessRecord,
    entries: &'a [factorseal::VaultEntryMetadata],
) -> Option<&'a factorseal::VaultEntryMetadata> {
    entries.iter().find(|entry| record.is_for(entry))
}

fn secret_name(record: &AccessRecord, entries: &[factorseal::VaultEntryMetadata]) -> String {
    if let Some(entry) = record_entry(record, entries) {
        return visible_text(&vault_entry_label(entry).0);
    }
    let name = match &record.address {
        Some(factorseal::SecretAddress::SecretSpec { address }) => {
            secret_spec_address_label(address).0
        }
        Some(factorseal::SecretAddress::Local { item, .. }) if is_secret_spec(record.scope) => {
            item.clone()
        }
        Some(factorseal::SecretAddress::Local { .. }) => "Deleted secret".to_owned(),
        None => format!(
            "Every secret in {}",
            String::from_utf8_lossy(&record.namespace)
        ),
    };
    visible_text(&name)
}

fn zoned(at: u64, zone: &TimeZone) -> Option<Zoned> {
    let seconds = i64::try_from(at).ok()?;
    Some(Timestamp::from_second(seconds).ok()?.to_zoned(zone.clone()))
}

fn day_label(at: &Zoned, today: &Zoned) -> String {
    let (day, today) = (at.date(), today.date());
    if day == today {
        "Today".to_owned()
    } else if today.yesterday().is_ok_and(|yesterday| yesterday == day) {
        "Yesterday".to_owned()
    } else if day.year() == today.year() {
        at.strftime("%-d %B").to_string()
    } else {
        at.strftime("%-d %B %Y").to_string()
    }
}

pub(super) struct ActivityRow<'a> {
    day: String,
    reads: Vec<(&'a AccessRecord, Zoned)>,
}

pub(super) type ActivityKey = (String, AccessRecord);

impl ActivityRow<'_> {
    fn record(&self) -> &AccessRecord {
        self.reads[0].0
    }

    fn count(&self) -> u32 {
        self.reads
            .iter()
            .fold(0, |count, (record, _)| count.saturating_add(record.count))
    }

    fn last(&self) -> &Zoned {
        &self.reads[0].1
    }

    fn key(&self) -> ActivityKey {
        (self.day.clone(), self.record().clone())
    }

    fn matches(&self, (day, record): &ActivityKey) -> bool {
        self.day == *day && same_read(self.record(), record)
    }
}

fn same_read(left: &AccessRecord, right: &AccessRecord) -> bool {
    left.outcome == right.outcome
        && left.requester == right.requester
        && left.scope == right.scope
        && left.namespace == right.namespace
        && left.address == right.address
}

fn activity_rows<'a>(
    records: &'a [AccessRecord],
    zone: &TimeZone,
    today: &Zoned,
) -> Vec<ActivityRow<'a>> {
    let mut rows: Vec<ActivityRow<'a>> = Vec::new();
    for record in records {
        let Some(at) = zoned(record.at, zone) else {
            continue;
        };
        let day = day_label(&at, today);
        match rows
            .iter_mut()
            .rev()
            .take_while(|row| row.day == day)
            .find(|row| same_read(row.record(), record))
        {
            Some(row) => row.reads.push((record, at)),
            None => rows.push(ActivityRow {
                day,
                reads: vec![(record, at)],
            }),
        }
    }
    rows
}

fn activity_position(rows: &[ActivityRow], selected: Option<&ActivityKey>) -> usize {
    selected
        .and_then(|key| rows.iter().position(|row| row.matches(key)))
        .unwrap_or(0)
}

fn clock(at: &Zoned) -> String {
    at.strftime("%H:%M").to_string()
}

fn requester_details(requester: &AccessRequester) -> Vec<(&'static str, String)> {
    match requester {
        AccessRequester::Program {
            principal,
            application,
        } => {
            let mut details = vec![
                ("Application", visible_text(&principal.application_id)),
                (
                    "Executable digest",
                    hex_digest(&principal.executable_digest),
                ),
            ];
            if let Some(signer) = &principal.signer_id {
                details.push(("Signed by", visible_text(signer)));
            }
            if let Some(application) = application {
                for (label, value) in [
                    ("Project", &application.project),
                    ("Profile", &application.profile),
                    ("Project folder", &application.base_dir),
                    ("Reason", &application.reason),
                ] {
                    if let Some(value) = value {
                        details.push((label, visible_text(value)));
                    }
                }
            }
            details
        }
        AccessRequester::Browser { origin } | AccessRequester::Website { origin } => {
            vec![("Website", visible_text(origin))]
        }
        AccessRequester::App { package } => vec![("App", visible_text(package))],
    }
}

fn avatar_letter(name: &str) -> String {
    name.chars()
        .find(|character| character.is_alphanumeric())
        .map_or_else(|| "?".to_owned(), |letter| letter.to_uppercase().collect())
}

fn app_avatar(name: &str, size: f32, theme: &gpui_component::theme::Theme) -> Div {
    icon_tile(size, theme)
        .text_size(rems(size * 0.45))
        .font_semibold()
        .text_color(theme.foreground)
        .child(avatar_letter(name))
}

fn read_text(outcome: AccessOutcome, count: u32) -> String {
    match (outcome, count) {
        (AccessOutcome::Denied, 1) => "Denied".to_owned(),
        (AccessOutcome::Denied, count) => format!("Denied {count} times"),
        (AccessOutcome::Allowed, 1) => "Read once".to_owned(),
        (AccessOutcome::Allowed, count) => format!("Read {count} times"),
    }
}

fn outcome_text(outcome: AccessOutcome, count: u32) -> Option<String> {
    (outcome == AccessOutcome::Denied || count > 1).then(|| read_text(outcome, count))
}

fn outcome_label(
    outcome: AccessOutcome,
    count: u32,
    theme: &gpui_component::theme::Theme,
) -> Option<Div> {
    outcome_text(outcome, count).map(|text| read_label(outcome, text, theme))
}

fn read_label(outcome: AccessOutcome, text: String, theme: &gpui_component::theme::Theme) -> Div {
    let (icon, color, background) = match outcome {
        AccessOutcome::Denied => (IconName::CircleX, theme.danger, theme.danger.opacity(0.1)),
        AccessOutcome::Allowed => (IconName::Eye, theme.muted_foreground, theme.muted),
    };
    h_flex()
        .flex_none()
        .items_center()
        .gap_1()
        .px_1p5()
        .py_0p5()
        .rounded_md()
        .bg(background)
        .text_caption()
        .font_medium()
        .text_color(color)
        .child(gpui_component::Icon::new(icon).size(rems(0.75)))
        .child(text)
}

impl DesktopView {
    pub(super) fn refresh_access_log(&mut self, cx: &mut Context<Self>) {
        let Some(metadata) = self.snapshot.metadata().cloned() else {
            return;
        };
        let runtime = Arc::clone(&self.runtime);
        cx.spawn(async move |this, cx| {
            let result = smol::unblock(move || runtime.load_access_log(&metadata)).await;
            let _ = this.update(cx, |view, cx| {
                if let Snapshot::Unsealed { contents, .. } = &mut view.snapshot {
                    contents.complete_access_log(result);
                    cx.notify();
                }
            });
        })
        .detach();
    }

    pub(super) fn watch_access_log(&mut self, cx: &mut Context<Self>) {
        self.access_log_watch = Some(cx.spawn(async move |this, cx| {
            loop {
                smol::Timer::after(ACTIVITY_REFRESH).await;
                let watching = this.update(cx, |view, cx| {
                    let watching = !view.settings_open
                        && matches!(
                            view.selected_vault_item,
                            Some(VaultSelection::Activity | VaultSelection::Entry(_))
                        );
                    if watching && cx.global::<DesktopWindow>().visible {
                        view.refresh_access_log(cx);
                    }
                    watching
                });
                if !watching.unwrap_or(false) {
                    break;
                }
            }
        }));
    }

    pub(super) fn activity_rows(&self) -> Vec<ActivityRow<'_>> {
        let Some(contents) = self.unsealed_contents() else {
            return Vec::new();
        };
        let zone = TimeZone::system();
        let today = Zoned::now().with_time_zone(zone.clone());
        activity_rows(&contents.access_log, &zone, &today)
    }

    pub(super) fn selected_activity_row(&self) -> Option<usize> {
        let rows = self.activity_rows();
        (!rows.is_empty()).then(|| activity_position(&rows, self.selected_activity.as_ref()))
    }

    pub(super) fn open_activity_row(&mut self, index: usize) {
        self.selected_activity = self.activity_rows().get(index).map(ActivityRow::key);
    }

    pub(super) fn show_activity_for(
        &mut self,
        entry: &factorseal::VaultEntryMetadata,
        cx: &mut Context<Self>,
    ) {
        self.select_vault_item(VaultSelection::Activity, cx);
        self.selected_activity = self
            .activity_rows()
            .iter()
            .find(|row| row.record().is_for(entry))
            .map(ActivityRow::key);
    }

    pub(super) fn activity_day_heading(day: &str, first: bool, cx: &App) -> Div {
        let theme = cx.theme();
        div()
            .px_4()
            .pb_2()
            .when(first, gpui::Styled::pt_3)
            .when(!first, gpui::Styled::pt_4)
            .border_b_1()
            .border_color(theme.border)
            .text_caption()
            .font_semibold()
            .text_color(theme.muted_foreground)
            .child(day.to_owned())
    }

    pub(super) fn activity_list_row(
        row: gpui::Stateful<Div>,
        rows: &[ActivityRow],
        index: usize,
        current: bool,
        entries: &[factorseal::VaultEntryMetadata],
        cx: &App,
    ) -> (Option<String>, gpui::Stateful<Div>) {
        let Some(activity) = rows.get(index) else {
            return (None, row);
        };
        let theme = cx.theme();
        let record = activity.record();
        let requester = requester_name(record);
        let day = (index == 0 || rows[index - 1].day != activity.day).then(|| activity.day.clone());
        let row = row
            .when(record.outcome == AccessOutcome::Denied && !current, |row| {
                row.bg(theme.danger.opacity(0.06))
            })
            .child(app_avatar(&requester, 2., theme))
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .child(
                        div()
                            .min_w_0()
                            .font_semibold()
                            .truncate()
                            .when(record_entry(record, entries).is_none(), |name| {
                                name.text_color(theme.muted_foreground)
                            })
                            .child(secret_name(record, entries)),
                    )
                    .child(
                        div()
                            .min_w_0()
                            .text_caption()
                            .text_color(theme.muted_foreground)
                            .truncate()
                            .child(requester),
                    ),
            )
            .child(
                v_flex()
                    .flex_none()
                    .items_end()
                    .child(
                        div()
                            .text_caption()
                            .text_color(theme.muted_foreground)
                            .child(clock(activity.last())),
                    )
                    .children(
                        outcome_label(record.outcome, activity.count(), theme).map(Styled::py_0),
                    ),
            );
        (day, row)
    }

    pub(super) fn render_activity_state(&self, cx: &mut Context<Self>) -> Option<Div> {
        let contents = self.unsealed_contents()?;
        let page = v_flex().w_full().gap_6().p_6().child(Self::section_header(
            Glyph::Clock.into(),
            Self::section_title("Activity"),
            None,
            cx,
        ));
        if let Some(error) = &contents.access_log_error {
            let error = error.clone();
            return Some(page.child(self.render_error_notice(&error, true, cx)));
        }
        if !contents.access_log.is_empty() {
            return None;
        }
        let icon = gpui_component::Icon::from(Glyph::Clock)
            .size(rems(40. / 16.))
            .text_color(cx.theme().muted_foreground);
        Some(page.child(Self::empty_state(
            icon,
            "No activity yet",
            "When an app or browser extension reads one of your secrets, it shows up here.",
            cx,
        )))
    }

    pub(super) fn render_activity_detail(&self, index: usize, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme().clone();
        let rows = self.activity_rows();
        let (Some(activity), Some(contents)) = (rows.get(index), self.unsealed_contents()) else {
            return div();
        };
        let record = activity.record();
        let requester = requester_name(record);
        let selection = record_entry(record, &contents.entries)
            .map(|entry| VaultSelection::Entry(Box::new(entry.clone())));
        let reads = activity.reads.iter().map(|(read, at)| {
            h_flex()
                .w_full()
                .items_center()
                .justify_between()
                .gap_4()
                .py_3()
                .border_b_1()
                .border_color(theme.border)
                .child(div().font_medium().child(clock(at)))
                .child(read_label(
                    read.outcome,
                    read_text(read.outcome, read.count),
                    &theme,
                ))
        });
        v_flex()
            .w_full()
            .gap_4()
            .child(Self::section_header_tile(
                app_avatar(&requester, 56. / 16., &theme),
                Self::section_title(secret_name(record, &contents.entries)),
                Some(format!("{requester} · {}", activity.day).into()),
                cx,
            ))
            .child(Self::render_detail_rows(
                requester_details(&record.requester),
                cx,
            ))
            .when_some(selection, |detail, selection| {
                detail.child(
                    h_flex().child(
                        button("activity-open-secret")
                            .icon(IconName::ArrowRight)
                            .label("Open secret")
                            .on_click(cx.listener(move |view, _, _, cx| {
                                view.select_vault_item(selection.clone(), cx);
                            })),
                    ),
                )
            })
            .child(
                v_flex()
                    .w_full()
                    .gap_3()
                    .pt_2()
                    .child(div().text_heading().font_semibold().child("Reads"))
                    .child(v_flex().children(reads)),
            )
    }

    pub(super) fn render_recent_access(
        &self,
        entry: &factorseal::VaultEntryMetadata,
        cx: &mut Context<Self>,
    ) -> Option<Div> {
        let contents = self.unsealed_contents()?;
        let records: Vec<_> = contents
            .access_log
            .iter()
            .filter(|record| record.is_for(entry))
            .collect();
        if records.is_empty() {
            return None;
        }
        let theme = cx.theme().clone();
        let entry = entry.clone();
        let zone = TimeZone::system();
        let today = Zoned::now().with_time_zone(zone.clone());
        let rows = records.iter().take(RECENT_ON_ITEM).filter_map(|record| {
            let at = zoned(record.at, &zone)?;
            Some(
                h_flex()
                    .w_full()
                    .items_center()
                    .gap_3()
                    .py_3()
                    .border_b_1()
                    .border_color(theme.border)
                    .child(app_avatar(&requester_name(record), 1.75, &theme))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .truncate()
                            .child(requester_name(record)),
                    )
                    .children(outcome_label(record.outcome, record.count, &theme))
                    .child(
                        div()
                            .flex_none()
                            .text_body()
                            .text_color(theme.muted_foreground)
                            .child(format!(
                                "{} at {}",
                                day_label(&at, &today),
                                at.strftime("%H:%M")
                            )),
                    ),
            )
        });
        Some(
            v_flex()
                .w_full()
                .gap_3()
                .child(
                    h_flex()
                        .items_center()
                        .justify_between()
                        .child(div().text_heading().font_semibold().child("Recent access"))
                        .when(records.len() > RECENT_ON_ITEM, |header| {
                            header.child(
                                div().mr(rems(-0.5)).child(
                                    button("see-all-activity")
                                        .ghost()
                                        .small()
                                        .label("See all")
                                        .on_click(cx.listener(move |view, _, _, cx| {
                                            view.show_activity_for(&entry, cx);
                                        })),
                                ),
                            )
                        }),
                )
                .child(v_flex().children(rows)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use factorseal::{PermissionPrincipal, SecretAddress};

    fn record(requester: AccessRequester, scope: factorseal::DocumentKind) -> AccessRecord {
        AccessRecord {
            id: 0,
            at: 0,
            count: 1,
            outcome: AccessOutcome::Allowed,
            requester,
            scope,
            namespace: b"partition".to_vec(),
            address: Some(SecretAddress::new("token", None).unwrap()),
        }
    }

    fn program(path: &str) -> AccessRequester {
        AccessRequester::Program {
            principal: PermissionPrincipal {
                platform: factorseal::CallerPlatform::Linux,
                user_id: "1000".into(),
                application_id: path.into(),
                executable_digest: [0; 32],
                signer_id: None,
            },
            application: None,
        }
    }

    #[test]
    fn requesters_are_named_the_way_people_know_them() {
        let local = factorseal::DocumentKind::LocalKeyring;
        assert_eq!(
            requester_name(&record(program("/usr/bin/git"), local)),
            "git"
        );
        assert_eq!(
            requester_name(&record(
                program("/usr/lib/factorseal"),
                factorseal::DocumentKind::NetworkManagerWifi
            )),
            "NetworkManager"
        );
        assert_eq!(
            requester_name(&record(
                program("/usr/bin/factorseal"),
                factorseal::DocumentKind::SecretSpecProviderCache
            )),
            "SecretSpec"
        );
        let browser = AccessRequester::Browser {
            origin: "https://github.com".into(),
        };
        assert_eq!(requester_name(&record(browser, local)), "github.com");
        let app = AccessRequester::App {
            package: "com.example\u{202E}bank".into(),
        };
        assert_eq!(requester_name(&record(app, local)), "com.examplebank");
    }

    #[test]
    fn days_read_as_today_yesterday_or_a_date() {
        let zone = TimeZone::UTC;
        let today = zoned(1_800_000_000, &zone).unwrap();
        let day = |at: u64| day_label(&zoned(at, &zone).unwrap(), &today);
        assert_eq!(day(1_800_000_000 - 60), "Today");
        assert_eq!(day(1_800_000_000 - 86_400), "Yesterday");
        assert_eq!(day(1_800_000_000 - 5 * 86_400), "10 January");
        assert_eq!(day(1_700_000_000), "14 November 2023");
    }

    #[test]
    fn reads_of_one_secret_by_one_app_share_a_row_per_day() {
        let zone = TimeZone::UTC;
        let today = zoned(1_800_000_000, &zone).unwrap();
        let read = |at: u64, count: u32, outcome: AccessOutcome| AccessRecord {
            at,
            count,
            outcome,
            ..record(program("git"), factorseal::DocumentKind::LinuxSecretService)
        };
        let records = [
            read(1_800_000_000, 2, AccessOutcome::Allowed),
            read(1_800_000_000 - 600, 1, AccessOutcome::Denied),
            read(1_800_000_000 - 660, 3, AccessOutcome::Allowed),
            read(1_800_000_000 - 86_400, 1, AccessOutcome::Allowed),
        ];
        let rows = activity_rows(&records, &zone, &today);
        let summary: Vec<_> = rows
            .iter()
            .map(|row| {
                let reads: Vec<_> = row.reads.iter().map(|(_, at)| clock(at)).collect();
                (row.day.as_str(), row.count(), reads)
            })
            .collect();
        assert_eq!(
            summary,
            [
                ("Today", 5, vec!["08:00".to_owned(), "07:49".to_owned()]),
                ("Today", 1, vec!["07:50".to_owned()]),
                ("Yesterday", 1, vec!["08:00".to_owned()]),
            ]
        );
    }

    #[test]
    fn an_open_row_stays_open_when_new_reads_arrive() {
        let zone = TimeZone::UTC;
        let today = zoned(1_800_000_000, &zone).unwrap();
        let local = factorseal::DocumentKind::LocalKeyring;
        let git = AccessRecord {
            at: 1_800_000_000 - 600,
            ..record(program("/usr/bin/git"), local)
        };
        let before = [git.clone()];
        let key = activity_rows(&before, &zone, &today)[0].key();
        let after = [
            AccessRecord {
                at: 1_800_000_000,
                ..record(program("/usr/bin/curl"), local)
            },
            AccessRecord {
                at: 1_800_000_000 - 60,
                ..git.clone()
            },
            git,
        ];
        let rows = activity_rows(&after, &zone, &today);
        assert_eq!(activity_position(&rows, Some(&key)), 1);
        assert_eq!(rows[1].count(), 2);
        assert_eq!(activity_position(&rows, None), 0);
    }

    #[test]
    fn details_name_the_exact_program() {
        let AccessRequester::Program { principal, .. } = program("/usr/bin/git") else {
            unreachable!();
        };
        let requester = AccessRequester::Program {
            principal: PermissionPrincipal {
                executable_digest: [0xab; 32],
                signer_id: Some("Example Corp".into()),
                ..principal
            },
            application: Some(factorseal::DeclaredApplication {
                project: Some("shop".into()),
                profile: None,
                base_dir: Some("/home/me/shop".into()),
                reason: None,
            }),
        };
        assert_eq!(
            requester_details(&requester),
            [
                ("Application", "/usr/bin/git".to_owned()),
                ("Executable digest", "ab".repeat(32)),
                ("Signed by", "Example Corp".to_owned()),
                ("Project", "shop".to_owned()),
                ("Project folder", "/home/me/shop".to_owned()),
            ]
        );
        let browser = AccessRequester::Browser {
            origin: "https://github.com".into(),
        };
        assert_eq!(
            requester_details(&browser),
            [("Website", "https://github.com".to_owned())]
        );
    }

    #[test]
    fn repeated_reads_and_denials_are_counted() {
        assert_eq!(outcome_text(AccessOutcome::Allowed, 1), None);
        assert_eq!(read_text(AccessOutcome::Allowed, 1), "Read once");
        assert_eq!(
            outcome_text(AccessOutcome::Allowed, 3).as_deref(),
            Some("Read 3 times")
        );
        assert_eq!(
            outcome_text(AccessOutcome::Denied, 3).as_deref(),
            Some("Denied 3 times")
        );
        assert_eq!(
            outcome_text(AccessOutcome::Denied, 1).as_deref(),
            Some("Denied")
        );
    }

    #[test]
    fn avatars_show_the_apps_first_letter() {
        assert_eq!(avatar_letter("secret-tool"), "S");
        assert_eq!(avatar_letter("python3.14"), "P");
        assert_eq!(avatar_letter("über"), "Ü");
        assert_eq!(avatar_letter("--"), "?");
    }
}
