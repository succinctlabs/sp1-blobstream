#[allow(unused_imports)]
use sp1_build::{build_program_with_args, BuildArgs};

fn main() {
    build_program_with_args(
        "../program",
        BuildArgs {
            docker: true,
            elf_name: "blobstream-elf".to_string(),
            ..Default::default()
        },
    )
}
