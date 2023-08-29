use ocl::builders::ContextProperties;
use ocl::enums::ArgVal;
use ocl::prm::cl_ulong;
use ocl::{core, flags};
use rayon::prelude::*;
use reqwest;
use serde::Deserialize;
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::str;
use std::time::{Duration, Instant};


fn mnemonic_gpu(
    platform_id: core::types::abs::PlatformId,
    device_id: core::types::abs::DeviceId,
    src: std::ffi::CString,
    kernel_name: &String,
) -> ocl::core::Result<()> {
    let context_properties = ContextProperties::new().platform(platform_id);
    let context =
        core::create_context(Some(&context_properties), &[device_id], None, None).unwrap();
    let program = core::create_program_with_source(&context, &[src]).unwrap();
    core::build_program(
        &program,
        Some(&[device_id]),
        &CString::new("").unwrap(),
        None,
        None,
    )
    .unwrap_or_else(|e| {
        println!("Build error: {}", e);
      });
    let queue = core::create_command_queue(&context, &device_id, None).unwrap();
    let mut index: u64 = 0;
    loop {
        let start = Instant::now();
        let items: u64 = 100000;

        let mut res_address = vec![0u8; 20];
        let mut target_mnemonic = vec![0u8; 120];
        let mut mnemonic_found = vec![0u8; 1];
        let start_index: cl_ulong = index;
        // let mut all_indices = vec![[0u8; 12]; 1];

        // all_indices[0] = [403, 1293, 63, 900, 581, 666, 1640, 1414, 1208, 491, 1021, 1932];

        // let all_indices_buf = unsafe { core::create_buffer(&context, flags::MEM_READ_ONLY |
        //     flags::MEM_COPY_HOST_PTR, 120, Some(&all_indices))? };

        let res_address_buf = unsafe {
            core::create_buffer(
                &context,
                flags::MEM_WRITE_ONLY | flags::MEM_COPY_HOST_PTR,
                20,
                Some(&res_address),
            )?
        };

        let target_mnemonic_buf = unsafe {
            core::create_buffer(
                &context,
                flags::MEM_WRITE_ONLY | flags::MEM_COPY_HOST_PTR,
                120,
                Some(&target_mnemonic),
            )?
        };

        let mnemonic_found_buf = unsafe {
            core::create_buffer(
                &context,
                flags::MEM_WRITE_ONLY | flags::MEM_COPY_HOST_PTR,
                1,
                Some(&mnemonic_found),
            )?
        };

        let kernel = core::create_kernel(&program, kernel_name)?;

        // core::set_kernel_arg(&kernel, 0, ArgVal::mem(&all_indices_buf))?;
        core::set_kernel_arg(&kernel, 0, ArgVal::scalar(&start_index))?;
        core::set_kernel_arg(&kernel, 1, ArgVal::mem(&res_address_buf))?;
        core::set_kernel_arg(&kernel, 2, ArgVal::mem(&target_mnemonic_buf))?;
        core::set_kernel_arg(&kernel, 3, ArgVal::mem(&mnemonic_found_buf))?;

        unsafe {
            core::enqueue_kernel(
                &queue,
                &kernel,
                1,
                None,
                &[items as usize, 1, 1],
                None,
                None::<core::Event>,
                None::<&mut core::Event>,
            )?;
        }

        unsafe {
            core::enqueue_read_buffer(
                &queue,
                &res_address_buf,
                true,
                0,
                &mut res_address,
                None::<core::Event>,
                None::<&mut core::Event>,
            )?;
        }

        unsafe {
            core::enqueue_read_buffer(
                &queue,
                &target_mnemonic_buf,
                true,
                0,
                &mut target_mnemonic,
                None::<core::Event>,
                None::<&mut core::Event>,
            )?;
        }

        unsafe {
            core::enqueue_read_buffer(
                &queue,
                &mnemonic_found_buf,
                true,
                0,
                &mut mnemonic_found,
                None::<core::Event>,
                None::<&mut core::Event>,
            )?;
        }

        // log_work(work.offset);

        if mnemonic_found[0] == 0x01 {
            let s = match String::from_utf8((&target_mnemonic[0..120]).to_vec()) {
                Ok(v) => v,
                Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
            };
            let mnemonic = s.trim_matches(char::from(0));
            println!("{}", mnemonic);

            // let addr = match String::from_utf8((&res_address[0..20]).to_vec()) {
            //   Ok(v) => v,
            //   Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
            // };
            // let address = addr.trim_matches(char::from(0));
            println!("{}", hex::encode(res_address));

            break;
            // log_solution(work.offset, mnemonic.to_string());
        }
        index = index + items;
        if index > 478000000 {
            break;
        }
        let duration = start.elapsed();
        println!("Time elapsed in expensive_function() is: {:?}", duration);
    }
    return Ok(());
}

fn main() {
    let platform_id = core::default_platform().unwrap();
    let device_ids =
        core::get_device_ids(&platform_id, Some(ocl::flags::DEVICE_TYPE_GPU), None).unwrap();

    let int_to_address_kernel: String = "prems_int_to_address".to_string();
    let int_to_address_files = [
        "common",
        "ripemd",
        "sha2",
        "secp256k1_common",
        "secp256k1_scalar",
        "secp256k1_field",
        "secp256k1_group",
        "secp256k1_prec",
        "secp256k1",
        "address",
        "mnemonic_constants",
        "prems_common",
        "prems_int_to_address",
    ];

    let files = int_to_address_files;
    let kernel_name = int_to_address_kernel;

    let mut raw_cl_file = "".to_string();

    for file in &files {
        let file_path = format!("./cl/{}.cl", file);
        let file_str = fs::read_to_string(file_path).unwrap();
        raw_cl_file.push_str(&file_str);
        raw_cl_file.push_str("\n");
    }

    let src_cstring = CString::new(raw_cl_file).unwrap();

    device_ids.into_par_iter().for_each(move |device_id| {
        mnemonic_gpu(platform_id, device_id, src_cstring.clone(), &kernel_name).unwrap()
    });
}
