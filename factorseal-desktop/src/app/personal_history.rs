use super::*;

const LIMIT: usize = 50;

pub(super) enum Change {
    Edit(PersonalSecret),
    Delete(PersonalSecret),
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum Step<'a> {
    Put(&'a PersonalSecret),
    Remove(&'a str),
}

impl Change {
    pub(super) fn step(&self, direction: Direction) -> Step<'_> {
        match (self, direction) {
            (Self::Delete(item), Direction::Redo) => Step::Remove(&item.id),
            (Self::Edit(item) | Self::Delete(item), _) => Step::Put(item),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Direction {
    Undo,
    Redo,
}

impl Direction {
    pub(super) const fn opposite(self) -> Self {
        match self {
            Self::Undo => Self::Redo,
            Self::Redo => Self::Undo,
        }
    }
}

pub(super) struct History<T> {
    undo: Vec<T>,
    redo: Vec<T>,
}

impl<T> Default for History<T> {
    fn default() -> Self {
        Self {
            undo: Vec::new(),
            redo: Vec::new(),
        }
    }
}

impl<T> History<T> {
    pub(super) fn record(&mut self, change: T) {
        self.redo.clear();
        self.push(Direction::Undo, change);
    }

    pub(super) fn take(&mut self, direction: Direction) -> Option<T> {
        self.stack(direction).pop()
    }

    pub(super) fn keep(&mut self, direction: Direction, change: T) {
        self.push(direction, change);
    }

    pub(super) fn applied(&mut self, direction: Direction, inverse: T) {
        self.push(direction.opposite(), inverse);
    }

    pub(super) fn clear(&mut self) {
        self.undo.clear();
        self.redo.clear();
    }

    fn push(&mut self, direction: Direction, change: T) {
        let stack = self.stack(direction);
        stack.push(change);
        if stack.len() > LIMIT {
            stack.remove(0);
        }
    }

    fn stack(&mut self, direction: Direction) -> &mut Vec<T> {
        match direction {
            Direction::Undo => &mut self.undo,
            Direction::Redo => &mut self.redo,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_edit_never_removes_the_item() {
        let item = PersonalSecret::new(PersonalSecretKind::Login, "Alpha".into());
        let id = item.id.clone();
        let change = Change::Edit(item);
        for direction in [Direction::Undo, Direction::Redo] {
            assert!(matches!(change.step(direction), Step::Put(item) if item.id == id));
        }
    }

    #[test]
    fn a_delete_is_undone_by_putting_the_item_back() {
        let item = PersonalSecret::new(PersonalSecretKind::Login, "Alpha".into());
        let id = item.id.clone();
        let change = Change::Delete(item);
        assert!(matches!(change.step(Direction::Undo), Step::Put(item) if item.id == id));
        assert_eq!(change.step(Direction::Redo), Step::Remove(&id));
    }

    #[test]
    fn undo_and_redo_walk_back_and_forth() {
        let mut history = History::default();
        history.record(1);
        history.record(2);
        let change = history.take(Direction::Undo).unwrap();
        assert_eq!(change, 2);
        history.applied(Direction::Undo, 20);
        assert_eq!(history.take(Direction::Undo), Some(1));
        history.applied(Direction::Undo, 10);
        assert_eq!(history.take(Direction::Undo), None);
        assert_eq!(history.take(Direction::Redo), Some(10));
        history.applied(Direction::Redo, 1);
        assert_eq!(history.take(Direction::Redo), Some(20));
        history.applied(Direction::Redo, 2);
        assert_eq!(history.take(Direction::Redo), None);
        assert_eq!(history.take(Direction::Undo), Some(2));
    }

    #[test]
    fn a_new_change_drops_redo() {
        let mut history = History::default();
        history.record(1);
        let change = history.take(Direction::Undo).unwrap();
        history.applied(Direction::Undo, change);
        history.record(2);
        assert_eq!(history.take(Direction::Redo), None);
        assert_eq!(history.take(Direction::Undo), Some(2));
    }

    #[test]
    fn a_failed_step_keeps_its_change() {
        let mut history = History::default();
        history.record(1);
        let change = history.take(Direction::Undo).unwrap();
        history.keep(Direction::Undo, change);
        assert_eq!(history.take(Direction::Undo), Some(1));
        assert_eq!(history.take(Direction::Redo), None);
    }

    #[test]
    fn history_keeps_only_recent_changes() {
        let mut history = History::default();
        for change in 0..=LIMIT {
            history.record(change);
        }
        for change in (1..=LIMIT).rev() {
            assert_eq!(history.take(Direction::Undo), Some(change));
        }
        assert_eq!(history.take(Direction::Undo), None);
    }

    #[test]
    fn clearing_forgets_every_change() {
        let mut history = History::default();
        history.record(1);
        history.record(2);
        let change = history.take(Direction::Undo).unwrap();
        history.applied(Direction::Undo, change);
        history.clear();
        assert_eq!(history.take(Direction::Undo), None);
        assert_eq!(history.take(Direction::Redo), None);
    }
}
