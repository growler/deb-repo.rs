use {debrepo::exec::get_user_name, rustix::fs::Uid};

#[test]
fn get_user_name_returns_current_user_and_none_for_bogus() {
    let uid = rustix::process::geteuid();
    let name = get_user_name(uid);
    assert!(name.is_some(), "current user should have a name");
    assert!(!name.unwrap().is_empty());

    let bogus = get_user_name(Uid::from_raw(u32::MAX - 1));
    assert!(bogus.is_none(), "bogus uid should return None");
}
