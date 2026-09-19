use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ghostscope_ui::{
    components::{
        command_panel::{FileCompletionCache, InputHandler},
        source_panel::{SourceNavigation, SourceRenderer, SourceSearch},
    },
    model::panel_state::{CommandPanelState, SourcePanelState},
};
use ratatui::{backend::TestBackend, style::Color, Terminal};

fn search(lines: &[&str], query: &str) -> SourcePanelState {
    let mut state = SourcePanelState {
        content: lines.iter().map(|line| line.to_string()).collect(),
        ..SourcePanelState::default()
    };
    SourceSearch::enter_search_mode(&mut state);
    for ch in query.chars() {
        SourceSearch::push_search_char(&mut state, ch);
    }
    state
}

#[test]
fn unicode_search_uses_character_columns_for_navigation() {
    let mut state = search(&["// 中文注释", "// 🦀中文中", ""], "中");
    assert_eq!(state.search_matches, [(0, 3, 4), (1, 4, 5), (1, 6, 7)]);
    assert_eq!((state.cursor_line, state.cursor_col), (0, 3));

    SourceSearch::confirm_search(&mut state);
    SourceSearch::next_match(&mut state);
    assert_eq!((state.cursor_line, state.cursor_col), (1, 4));
    SourceSearch::next_match(&mut state);
    assert_eq!((state.cursor_line, state.cursor_col), (1, 6));
    SourceNavigation::move_left(&mut state);
    assert_eq!(state.cursor_col, 5);
    SourceSearch::next_match(&mut state);
    assert_eq!((state.cursor_line, state.cursor_col), (0, 3));
    SourceSearch::prev_match(&mut state);
    assert_eq!((state.cursor_line, state.cursor_col), (1, 6));
}

#[test]
fn unicode_search_keeps_overlapping_matches() {
    for (line, query, expected) in [
        ("中中中", "中中", vec![(0, 0, 2), (0, 1, 3)]),
        ("ééé", "ÉÉ", vec![(0, 0, 2), (0, 1, 3)]),
        ("🦀🦀🦀", "🦀🦀", vec![(0, 0, 2), (0, 1, 3)]),
        ("banana", "ANA", vec![(0, 1, 4), (0, 3, 6)]),
    ] {
        assert_eq!(search(&[line], query).search_matches, expected, "{line}");
    }
}

#[test]
fn unicode_search_maps_lowercase_matches_to_original_columns() {
    // İ expands to two characters; K shrinks from three UTF-8 bytes to one.
    for (query, expected) in [
        ("x", vec![(0, 3, 4)]),
        ("中", vec![(0, 4, 5)]),
        ("i\u{307}", vec![(0, 0, 1), (0, 2, 3), (0, 5, 6)]),
        ("k", vec![(0, 1, 2)]),
    ] {
        assert_eq!(
            search(&["İKİX中İ"], query).search_matches,
            expected,
            "{query}"
        );
    }
    // Preserve string lowercasing's contextual final sigma.
    assert_eq!(search(&["ΟΣ"], "ΟΣ").search_matches, [(0, 0, 2)]);
}

#[test]
fn unicode_search_backspace_clears_matches() {
    let mut state = search(&["// 中文注释"], "中文");
    assert_eq!(state.search_matches, [(0, 3, 5)]);
    SourceSearch::backspace_search(&mut state);
    assert_eq!(state.search_query, "中");
    assert_eq!(state.search_matches, [(0, 3, 4)]);
    SourceSearch::backspace_search(&mut state);
    assert!(state.search_query.is_empty());
    assert!(state.search_matches.is_empty());
    assert_eq!(state.current_match, None);
    SourceSearch::push_search_char(&mut state, '无');
    assert!(state.search_matches.is_empty());
}

#[test]
fn unicode_search_renders_highlights_on_original_text() {
    let mut state = search(&["// 中文注释"], "文注");
    let mut terminal = Terminal::new(TestBackend::new(40, 6)).unwrap();
    terminal
        .draw(|frame| {
            SourceRenderer::render(
                frame,
                frame.area(),
                &mut state,
                &FileCompletionCache::default(),
                true,
            );
        })
        .unwrap();

    let buffer = terminal.backend().buffer();
    for (x, symbol, color) in [
        (9, "中", Color::DarkGray),
        (11, "文", Color::LightMagenta),
        (13, "注", Color::LightMagenta),
        (15, "释", Color::DarkGray),
    ] {
        assert_eq!(buffer[(x, 1)].symbol(), symbol);
        assert_eq!(buffer[(x, 1)].fg, color, "{symbol}");
    }
}

#[test]
fn unicode_file_completion_returns_whole_common_characters() {
    for (files, input, expected) in [
        (["a中文1.c", "a中文2.c"], "source a", Some("中文")),
        (["a中文件1.c", "a中文件2.c"], "source a", Some("中文件")),
        (["a🦀é1.c", "a🦀é2.c"], "source a", Some("🦀é")),
        (["a中文1.c", "a中语2.c"], "source a", None),
        (["a中文1.c", "a文中2.c"], "source a", None),
        (["a中文.c", "a中文.cxx"], "source a中文.c", None),
        (
            ["/project/src/中文/a1.c", "/project/src/中文/a2.c"],
            "source src/",
            Some("中文/a"),
        ),
    ] {
        let mut cache = FileCompletionCache::new(&files.map(String::from));
        assert_eq!(
            cache.get_file_completion(input).as_deref(),
            expected,
            "{input}"
        );
    }
}

#[test]
fn unicode_file_completion_handles_lowercase_length_changes() {
    for (file, input, expected) in [
        ("K中文.c", "source k", "中文.c"),
        ("K中文.c", "source K", "中文.c"),
        ("İ文件.c", "source i\u{307}", "文件.c"),
        ("src/İ文件.c", "source src/i\u{307}", "文件.c"),
        // A prefix ending inside İ's lowercase expansion cannot be sliced off.
        ("İ文件.c", "source i", ""),
    ] {
        let mut cache = FileCompletionCache::new(&[file.to_string()]);
        assert_eq!(
            cache.get_file_completion(input).as_deref(),
            Some(expected),
            "{input}"
        );
    }
}

#[test]
fn unicode_tab_completion_keeps_the_input_cursor_in_characters() {
    let mut state = CommandPanelState::new();
    state.file_completion_cache = Some(FileCompletionCache::new(&[
        "a中文1.c".to_string(),
        "a中文2.c".to_string(),
    ]));
    for ch in "source a".chars() {
        InputHandler::insert_char(&mut state, ch);
    }
    InputHandler::handle_key_event(&mut state, KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(state.input_text, "source a中文");
    assert_eq!(state.cursor_position, 10);

    InputHandler::insert_char(&mut state, '1');
    InputHandler::handle_key_event(&mut state, KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(state.input_text, "source a中文1.c");
    assert_eq!(state.cursor_position, 13);
    InputHandler::delete_char(&mut state);
    assert_eq!(state.input_text, "source a中文1.");
    assert_eq!(state.cursor_position, 12);
}
