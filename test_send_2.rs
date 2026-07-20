trait MyTrait: Send + Sync {}
fn assert_send<T: Send>(_: T) {}
fn test(x: std::sync::Arc<dyn MyTrait>) {
    let fut = async move {
        let y = x;
        async {}.await;
    };
    assert_send(fut);
}
