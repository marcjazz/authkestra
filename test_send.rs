trait MyTrait: Send + Sync {}
fn assert_send<T: Send>(_: T) {}
async fn my_async(t: &dyn MyTrait) {}
fn test<'a>(x: &'a dyn MyTrait) {
    let fut = my_async(x);
    assert_send(fut);
}
