use std::io::{self, Read, Write};
use std::process;
use std::u8;

static mut seed0 : u64 = 0x48335830527b4661;
static mut seed1 : u64 = 0x6B655F466C61677D;

struct Console {
}
impl Console{
	fn get<T:Sized + std::str::FromStr>()->Option<T> {
	let mut stdout = io::stdout();
	stdout.flush();
	let input = {
		let mut stdin = io::stdin();
	let mut input = String::new();
	stdin.read_line(&mut input);
	input
	};
	let v : T = match input.trim().parse::<T>() {
		Err(e) => {
			process::exit(0);
		},
			Ok(v) => v
	};
	return Some(v);
}
}


fn xorshift128plus() -> u64
{
	unsafe
	{
		let mut x = seed0;
	let y = seed1;
	seed0 = y;
	x ^= x << 23;
	seed1 = x ^ y ^ (x >> 17) ^ (y >> 26);
	return seed1 + y;
	}


}

fn main() {
	print!("Input Number (Part 1)>>");
	let a = Console::get::<i32>().unwrap();
	if a == 0x6863
	{

		//wHo48o&*
		print!("Next. Input String(Part 2)>>");

		let inpS = Console::get::<String>().unwrap();
		let mut isStage2 = false;
		
		if inpS.len() == 8
		{
			let mut bytes = inpS.bytes();
			if bytes.next() == Some((xorshift128plus() & 0x7f) as u8)
			{
				if bytes.next() == Some((xorshift128plus() & 0x7f) as u8)
				{
					if bytes.next() == Some((xorshift128plus() & 0x7f) as u8)
					{
						if bytes.next() == Some((xorshift128plus() & 0x7f) as u8)
						{
							if bytes.next() == Some((xorshift128plus() & 0x7f) as u8)
							{
								if bytes.next() == Some((xorshift128plus() & 0x7f) as u8)
								{
									if bytes.next() == Some((xorshift128plus() & 0x7f) as u8)
									{
										if bytes.next() == Some((xorshift128plus() & 0x7f) as u8)
										{
											isStage2 = true;
										}
									}
								}
							}
						}
					}
				}
			}
		}
		
		if isStage2 == true
		{
			print!("F");
			print!("l");
			print!("a");
			print!("g");
			print!(":");
			
			print!("H");
			print!("3");
			print!("X");
			print!("0");
			print!("R");
			print!("{{");
			print!("{}",inpS);
			print!("_");
			let s: String = a.to_string();
			print!("{}",s);
			
			println!("}}");
			
		}
	}
}