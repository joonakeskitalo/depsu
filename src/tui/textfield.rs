//! Text being edited in a dialog: the text and a cursor in it. Lines are split at `\n`.

#[derive(Clone, Debug, Default, PartialEq)]
pub struct TextField {
    text: String,
    /// Byte offset of the cursor, always on a character boundary.
    cursor: usize,
}

impl TextField {
    /// `text`, with the cursor at its end.
    pub fn new(text: impl Into<String>) -> Self {
        let text = text.into();
        let cursor = text.len();
        TextField { text, cursor }
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Replaces the text, with the cursor at its end.
    pub fn set(&mut self, text: impl Into<String>) {
        *self = TextField::new(text);
    }

    pub fn insert(&mut self, c: char) {
        self.text.insert(self.cursor, c);
        self.cursor += c.len_utf8();
    }

    /// Deletes the character before the cursor. False when there is none.
    pub fn backspace(&mut self) -> bool {
        match self.text[..self.cursor].chars().next_back() {
            Some(c) => {
                self.cursor -= c.len_utf8();
                self.text.remove(self.cursor);
                true
            }
            None => false,
        }
    }

    /// Deletes the character under the cursor. False when there is none.
    pub fn delete(&mut self) -> bool {
        if self.cursor < self.text.len() {
            self.text.remove(self.cursor);
            true
        } else {
            false
        }
    }

    pub fn left(&mut self) {
        if let Some(c) = self.text[..self.cursor].chars().next_back() {
            self.cursor -= c.len_utf8();
        }
    }

    pub fn right(&mut self) {
        if let Some(c) = self.text[self.cursor..].chars().next() {
            self.cursor += c.len_utf8();
        }
    }

    fn line_start(&self, at: usize) -> usize {
        self.text[..at].rfind('\n').map_or(0, |i| i + 1)
    }

    fn line_end(&self, at: usize) -> usize {
        self.text[at..].find('\n').map_or(self.text.len(), |i| at + i)
    }

    /// To the start of the line.
    pub fn home(&mut self) {
        self.cursor = self.line_start(self.cursor);
    }

    /// To the end of the line.
    pub fn end(&mut self) {
        self.cursor = self.line_end(self.cursor);
    }

    /// Characters from the start of the line to the cursor.
    fn column(&self) -> usize {
        self.text[self.line_start(self.cursor)..self.cursor].chars().count()
    }

    /// `col` characters into the line starting at `start`, or its end if it is shorter.
    fn at_column(&self, start: usize, col: usize) -> usize {
        let end = self.line_end(start);
        self.text[start..end]
            .char_indices()
            .nth(col)
            .map_or(end, |(i, _)| start + i)
    }

    /// To the line above, keeping the column where it can.
    pub fn up(&mut self) {
        let start = self.line_start(self.cursor);
        if start == 0 {
            return;
        }
        let col = self.column();
        self.cursor = self.at_column(self.line_start(start - 1), col);
    }

    /// To the line below, keeping the column where it can.
    pub fn down(&mut self) {
        let end = self.line_end(self.cursor);
        if end == self.text.len() {
            return;
        }
        let col = self.column();
        self.cursor = self.at_column(end + 1, col);
    }

    /// The line the cursor is on, counting from 0.
    pub fn cursor_line(&self) -> usize {
        self.text[..self.cursor].matches('\n').count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edits_at_the_cursor() {
        let mut f = TextField::new("chore: upgrade");
        f.home();
        for _ in 0.."chore".len() {
            f.delete();
        }
        for c in "fix".chars() {
            f.insert(c);
        }
        assert_eq!(f.text(), "fix: upgrade");
        f.end();
        assert!(f.backspace());
        assert_eq!(f.text(), "fix: upgrad");
        f.home();
        assert!(!f.backspace(), "nothing before the start");
        f.end();
        assert!(!f.delete(), "nothing after the end");
    }

    #[test]
    fn moves_between_lines_keeping_the_column() {
        let mut f = TextField::new("Fixes:\n- A-1: short\n- B-2: a longer title");
        assert_eq!(f.cursor_line(), 2);
        f.home();
        for _ in 0..4 {
            f.right();
        }
        f.up();
        assert_eq!(f.cursor_line(), 1);
        f.insert('X');
        assert_eq!(f.text(), "Fixes:\n- A-X1: short\n- B-2: a longer title");
        // Up onto a shorter line: its end.
        f.up();
        f.end();
        f.down();
        f.down();
        f.insert('!');
        assert_eq!(f.text(), "Fixes:\n- A-X1: short\n- B-2:! a longer title");
        // At the first or last line, up and down stay put.
        let mut f = TextField::new("one");
        f.up();
        f.down();
        assert_eq!(f.cursor(), 3);
    }

    #[test]
    fn whole_lines_can_be_removed() {
        let mut f = TextField::new("Fixes:\n- A-1: a\n- B-2: b");
        f.up(); // onto "- A-1: a"
        f.end();
        while f.cursor() > "Fixes:".len() {
            f.backspace();
        }
        assert_eq!(f.text(), "Fixes:\n- B-2: b");
    }

    #[test]
    fn handles_characters_wider_than_a_byte() {
        let mut f = TextField::new("päivitä ✔");
        f.left();
        f.left();
        f.insert('→');
        assert_eq!(f.text(), "päivitä→ ✔");
        f.home();
        f.right();
        assert!(f.delete());
        assert_eq!(f.text(), "pivitä→ ✔");
    }
}
