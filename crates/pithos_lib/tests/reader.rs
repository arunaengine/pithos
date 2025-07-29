#[cfg(test)]
mod tests {
    use pithos_lib::io::pithosreader::PithosReaderSimple;

    #[test]
    fn test_reader() {
        let pithos_file = "/tmp/test.pith".to_string();
        let key_pem = "tests/data/recipient1_private.pem".to_string();

        let mut pithos_reader = PithosReaderSimple::new(pithos_file, key_pem).unwrap();

        let _dir = pithos_reader.read_directory().unwrap();
        //println!("{:#?}", dir)
    }
}