use std::fmt;
use std::fmt::Display;

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum Token {
    Selection(String),
    Not,
    And,
    Or,
    OpeningParenthesis,
    ClosingParenthesis,
    OneOf(String),
    AllOf(String),
    OneOfThem,
    AllOfThem,
    End,
}

impl Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Selection(s) => write!(f, "{}", s),
            Self::Not => write!(f, "not"),
            Self::And => write!(f, "and"),
            Self::Or => write!(f, "or"),
            Self::OpeningParenthesis => write!(f, "("),
            Self::ClosingParenthesis => write!(f, ")"),
            Self::OneOf(s) => write!(f, "1 of {}", s),
            Self::AllOf(s) => write!(f, "all of {}", s),
            Self::OneOfThem => write!(f, "1 of them"),
            Self::AllOfThem => write!(f, "all them"),
            Self::End => write!(f, "<END>"),
        }
    }
}

enum Quantifier {
    One,
    All(String),
}

impl Display for Quantifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::One => write!(f, "1"),
            Self::All(case) => write!(f, "{}", case),
        }
    }
}

pub(crate) struct Lexer {
    tokens: Vec<Token>,
}

impl Lexer {
    pub(crate) fn new(input: &str) -> Self {
        let mut tokens = Self::tokenize(input);
        tokens.reverse();
        Self { tokens }
    }

    pub(crate) fn next(&mut self) -> Token {
        self.tokens.pop().unwrap_or(Token::End)
    }
    pub(crate) fn peek(&mut self) -> Token {
        self.tokens.last().cloned().unwrap_or(Token::End)
    }

    fn tokenize(input: &str) -> Vec<Token> {
        let mut tokens: Vec<Token> = Vec::new();

        let mut start = 0_usize;

        let mut quanitifer: Option<Quantifier> = None;
        let mut of_keyword = false;
        let input_len = input.len();

        for (i, char) in input.chars().enumerate() {
            let is_last = i == input_len - 1;
            let is_whitespace = char.is_ascii_whitespace();
            let is_opening_parenthesis = char == '(';
            let is_closing_parenthesis = char == ')';
            let is_parenthesis = is_opening_parenthesis || is_closing_parenthesis;

            if !is_parenthesis && !is_whitespace && !is_last {
                continue;
            } else if is_whitespace && start == i {
                start = i + 1;
                continue;
            }
            // if we didn't continue, we are either at a space, a parenthesis or at the last character

            let end = if is_last && !is_whitespace && !is_parenthesis {
                i + 1
            } else {
                i
            };

            if let Some(q) = &quanitifer {
                if !of_keyword && input[start..end].to_lowercase() == "of" {
                    of_keyword = true;
                    if !is_last {
                        start = i + 1;
                        continue;
                    } else {
                        tokens.push(Token::Selection(q.to_string()));
                    }
                } else if !of_keyword {
                    tokens.push(Token::Selection(q.to_string()));
                    quanitifer = None
                }
            }

            match input[start..end].to_lowercase().as_str() {
                "" => {}
                "not" => tokens.push(Token::Not),
                "and" => tokens.push(Token::And),
                "or" => tokens.push(Token::Or),
                "(" => tokens.push(Token::OpeningParenthesis),
                ")" => tokens.push(Token::ClosingParenthesis),
                "1" => quanitifer = Some(Quantifier::One),
                "all" => quanitifer = Some(Quantifier::All(input[start..end].to_string())),
                c if quanitifer.is_some() && of_keyword => {
                    match quanitifer {
                        Some(Quantifier::One) => {
                            if c == "them" {
                                tokens.push(Token::OneOfThem);
                            } else {
                                tokens.push(Token::OneOf(input[start..end].to_string()));
                            }
                        }
                        Some(Quantifier::All(_)) => {
                            if c == "them" {
                                tokens.push(Token::AllOfThem);
                            } else {
                                tokens.push(Token::AllOf(input[start..end].to_string()));
                            }
                        }
                        None => {}
                    }

                    quanitifer = None;
                    of_keyword = false;
                }
                _ => tokens.push(Token::Selection(input[start..end].to_string())),
            }
            if is_opening_parenthesis {
                tokens.push(Token::OpeningParenthesis)
            } else if is_closing_parenthesis {
                tokens.push(Token::ClosingParenthesis)
            }
            start = i + 1;
        }
        tokens
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenize_empty() {
        assert_eq!(Lexer::tokenize(""), vec![]);
        assert_eq!(Lexer::tokenize(" "), vec![]);
        assert_eq!(Lexer::tokenize("   "), vec![]);
    }

    #[test]
    fn test_tokenize_and_or() {
        let input = " selection_1 and selection_2   OR  selection_3 ";
        let tokens = Lexer::tokenize(input);
        assert_eq!(
            tokens,
            vec![
                Token::Selection("selection_1".to_string()),
                Token::And,
                Token::Selection("selection_2".to_string()),
                Token::Or,
                Token::Selection("selection_3".to_string())
            ]
        );
    }

    #[test]
    fn test_tokenize_1_of() {
        let input = "selection_1 and 1 OF ms*";
        let tokens = Lexer::tokenize(input);
        assert_eq!(
            tokens,
            vec![
                Token::Selection("selection_1".to_string()),
                Token::And,
                Token::OneOf("ms*".to_string()),
            ]
        );
    }

    #[test]
    fn test_tokenize_all_of() {
        let expected = vec![
            Token::OpeningParenthesis,
            Token::Selection("selection_1".to_string()),
            Token::And,
            Token::Selection("selection_2".to_string()),
            Token::ClosingParenthesis,
            Token::Or,
            Token::AllOfThem,
        ];
        let tokens = Lexer::tokenize("( selection_1 and selection_2 ) or all of them");
        assert_eq!(tokens, expected);

        let tokens = Lexer::tokenize("( selection_1 and selection_2 ) or all   of   them");
        assert_eq!(tokens, expected);
    }

    #[test]
    fn test_tokenize_wrong_all_of() {
        let input = "( selection_1 and selection_2 ) or aLL   oof thEm";
        let tokens = Lexer::tokenize(input);
        assert_eq!(
            tokens,
            vec![
                Token::OpeningParenthesis,
                Token::Selection("selection_1".to_string()),
                Token::And,
                Token::Selection("selection_2".to_string()),
                Token::ClosingParenthesis,
                Token::Or,
                Token::Selection("aLL".to_string()),
                Token::Selection("oof".to_string()),
                Token::Selection("thEm".to_string())
            ]
        );
    }

    #[test]
    fn test_tokenize_no_spaces_around_parenthesis() {
        let input = "(selection_1 and selection_2) or all of them";
        let tokens = Lexer::tokenize(input);
        assert_eq!(
            tokens,
            vec![
                Token::OpeningParenthesis,
                Token::Selection("selection_1".to_string()),
                Token::And,
                Token::Selection("selection_2".to_string()),
                Token::ClosingParenthesis,
                Token::Or,
                Token::AllOfThem
            ]
        );
    }

    #[test]
    fn test_tokenize_long_expression() {
        let input = " write TargetLogonId from selection1 (if not selection2)";
        let tokens = Lexer::tokenize(input);
        assert_eq!(
            tokens,
            vec![
                Token::Selection("write".to_string()),
                Token::Selection("TargetLogonId".to_string()),
                Token::Selection("from".to_string()),
                Token::Selection("selection1".to_string()),
                Token::OpeningParenthesis,
                Token::Selection("if".to_string()),
                Token::Not,
                Token::Selection("selection2".to_string()),
                Token::ClosingParenthesis,
            ]
        );
    }
}
