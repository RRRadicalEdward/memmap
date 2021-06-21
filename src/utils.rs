pub fn array_i8_to_string(array: &[i8]) -> String {
    String::from_utf8(
        array
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&symbol| symbol as u8)
            .collect::<Vec<u8>>(),
    )
    .expect("We have valid UTF8 characters")
}
