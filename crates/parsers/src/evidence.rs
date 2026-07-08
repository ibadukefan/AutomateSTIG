use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceTranscript {
    pub hostname: Option<String>,
    pub outputs: HashMap<String, String>,
}

pub fn parse_evidence_transcript(raw: &str) -> EvidenceTranscript {
    let mut transcript = EvidenceTranscript {
        hostname: None,
        outputs: HashMap::new(),
    };
    let mut current_command: Option<String> = None;
    let mut current_output = String::new();

    for line in raw.lines() {
        if let Some(command) = line.strip_prefix("### automatestig:command ") {
            flush_output(
                &mut transcript.outputs,
                &mut current_command,
                &mut current_output,
            );
            current_command = Some(command.to_string());
            continue;
        }

        if let Some(hostname) = line.strip_prefix("### automatestig:hostname ") {
            transcript.hostname = Some(hostname.to_string());
            continue;
        }

        if current_command.is_some() {
            current_output.push_str(line);
            current_output.push('\n');
        }
    }

    flush_output(
        &mut transcript.outputs,
        &mut current_command,
        &mut current_output,
    );

    transcript
}

fn flush_output(
    outputs: &mut HashMap<String, String>,
    current_command: &mut Option<String>,
    current_output: &mut String,
) {
    if let Some(command) = current_command.take() {
        outputs.insert(command, current_output.trim_end().to_string());
        current_output.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_two_commands() {
        let transcript = parse_evidence_transcript(
            "### automatestig:command first command\nfirst output\n\
             ### automatestig:command second command\nsecond output\n",
        );

        assert_eq!(
            transcript.outputs.get("first command"),
            Some(&"first output".to_string())
        );
        assert_eq!(
            transcript.outputs.get("second command"),
            Some(&"second output".to_string())
        );
    }

    #[test]
    fn parses_hostname_line() {
        let transcript = parse_evidence_transcript(
            "### automatestig:hostname ontap01\n\
             ### automatestig:command system timeout show\noutput\n",
        );

        assert_eq!(transcript.hostname, Some("ontap01".to_string()));
        assert_eq!(
            transcript.outputs.get("system timeout show"),
            Some(&"output".to_string())
        );
    }

    #[test]
    fn ignores_preamble() {
        let transcript = parse_evidence_transcript(
            "ignored\nalso ignored\n\
             ### automatestig:command cluster date show\ncaptured\n",
        );

        assert_eq!(transcript.outputs.len(), 1);
        assert_eq!(
            transcript.outputs.get("cluster date show"),
            Some(&"captured".to_string())
        );
    }

    #[test]
    fn parses_empty_output_section() {
        let transcript = parse_evidence_transcript(
            "### automatestig:command empty command\n\
             ### automatestig:command next command\nnext output\n",
        );

        assert_eq!(
            transcript.outputs.get("empty command"),
            Some(&String::new())
        );
        assert_eq!(
            transcript.outputs.get("next command"),
            Some(&"next output".to_string())
        );
    }
}
