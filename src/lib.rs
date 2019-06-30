extern crate rand;
#[macro_use]
extern crate amcl_wrapper;
/*#[macro_use]
extern crate error_chain;*/
#[macro_use] extern crate failure;

pub mod setup;
pub mod errors;
pub mod signature;


/*macro_rules! tuplet {
 { ($y:ident $(, $x:ident)*) = $v:expr } => {
    let ($y,$($x),*, _) = tuplet!($v ; 1 ; ($($x),*) ; ($v.get(0)) ); };
 { ($y:ident , * $x:ident) = $v:expr } => {
    let ($y,$x) = tuplet!($v ; 1 ; () ; ($v.get(0)) ); };
 { ($y:ident $(, $x:ident)* , * $z:ident) = $v:expr } => {
    let ($y,$($x),*, $z) = tuplet!($v ; 1 ; ($($x),*) ; ($v.get(0)) ); };
 { $v:expr ; $j:expr ; ($y:ident $(, $x:ident)*) ; ($($a:expr),*)  } => {
    tuplet!( $v ; $j+1 ; ($($x),*) ; ($($a),*,$v.get($j)) ) };
 { $v:expr ; $j:expr ; () ; ($($a:expr),*) } => {
   {
    if $v.len() >= $j {
        let remain = $v.len() - $j;
        if remain > 0 {
            ($($a),*, $v[$j..])
        } else {
            ($($a),*, 0)
        }
    } else {
        ($($a),*, 0)
    }
   }
 }
}*/

/*macro_rules! tuplet {
 { ($y:ident $(, $x:ident)*) = $v:expr } => {
    let ($y,$($x),*, _) = tuplet!($v ; 1 ; ($($x),*) ; ($v.get(0)) ); };
 { ($y:ident , * $x:ident) = $v:expr } => {
    let ($y,$x) = tuplet!($v ; 1 ; () ; ($v.get(0)) ); };
 { ($y:ident $(, $x:ident)* , * $z:ident) = $v:expr } => {
    let ($y,$($x),*, $z) = tuplet!($v ; 1 ; ($($x),*) ; ($v.get(0)) ); };
 { $v:expr ; $j:expr ; ($y:ident $(, $x:ident)*) ; ($($a:expr),*)  } => {
    tuplet!( $v ; $j+1 ; ($($x),*) ; ($($a),*,$v.get($j)) ) };
 { $v:expr ; $j:expr ; () ; ($($a:expr),*) } => {
   {
    if $v.len() >= $j {
        let remain = $v.len() - $j;
        if remain > 0 {
            ($($a),*, Some(&$v[$j..]))
        } else {
            ($($a),*, None)
        }
    } else {
        ($($a),*, None)
    }
   }
 }
}*/

/*#[test]
fn ex1() {
    println!("=> ex1");

    let v = vec![1, 2, 3];

    tuplet!((a,b) = v);

    println!("a = {:?}", a);
    println!("b = {:?}", b);

    let v1 = vec![1, 2, 3];
    tuplet!((x,y,z,q) = v);
    println!("x = {:?}", x);
    println!("y = {:?}", y);
    println!("z = {:?}", z);
    println!("q = {:?}", q);
}*/

/*
#[test]
fn ex2() {
    println!("=> ex2");

    let v: Vec<i32> = vec![1, 2, 3];

    tuplet!((a,b,c,d) = v); // return d as None

    println!("a = {:?}", a);
    println!("b = {:?}", b);
    println!("c = {:?}", c);
    println!("d = {:?}", d);
}

#[test]
fn ex11() {
    println!("=> ex1");

    let v: Vec<i32> = vec![1, 2, 3];

    tuplet!((a,b) = v);

    println!("a = {:?}", a);
    println!("b = {:?}", b);
}*/
