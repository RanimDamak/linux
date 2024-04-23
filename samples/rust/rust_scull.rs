
use kernel::io_buffer::{IoBufferReader, IoBufferWriter};
use kernel::{file, miscdev};
use kernel::prelude::*;
use kernel::sync::{Arc, ArcBorrow};
use kernel::str::CString;
use alloc::vec::Vec;
use kernel::str::CStr;

//use alloc::slice::Concat;

use kernel::file::flags::O_WRONLY;


module! {
    type: Scull,
    name: "scull_test",
    license: "GPL",
}

struct Obd2Frame {
    length: u8,
    mode: u8,
    pid: u8,
    data: Vec<u8>,
} 

struct Scull {
    _dev: Pin<Box<miscdev::Registration<Scull>>>,
}

struct Device {
    obd2_frame: Obd2Frame,
}

impl Device {

    fn new() -> Self {
        let mut vec = Vec::new();
        let _ = vec.try_push(0x11);
        let _ = vec.try_push(0x0D);
        let obd2_frame = Obd2Frame::new_request(
            2,
            1,
            0x1,
            vec,
        );
        Device {
            obd2_frame: obd2_frame,
        }
    }

    fn get_obd2_frame(&self) -> &Obd2Frame {
        &self.obd2_frame
    }

}




#[vtable]

impl file::Operations for Scull{
    type OpenData = Arc<Device>;
    type Data = Arc<Device>;

    fn open(context: &Self::OpenData, _file: &file::File) -> Result<Self::Data> {
        let obd2_frame = context.get_obd2_frame();
        pr_info!("File for device {} was opened\n", obd2_frame.get_pid());
        Ok(context.clone())
    }

    fn read(
        _data: ArcBorrow<'_, Device>,
        _file: &file::File,
        _writer: &mut impl IoBufferWriter,
        _offset: u64,
    ) -> Result<usize> {
        pr_info!("File was read\n");
        Ok(0)
    }

    fn write(
        _data: ArcBorrow<'_, Device>,
        _file: &file::File,
        reader: &mut impl IoBufferReader,
        _offset: u64,
    ) -> Result<usize> {

        // let mut buffer = [0u8; 256];
        // let len = reader.read(&mut buffer)?;

        // if len > 0 {

        //     // let data = &buffer[..len];
        //     // let mut payload = Vec::new();
        //     // payload.try_extend_from_slice(&[len as u8, 0x01, 0x0D]);
        //     // payload.try_extend_from_slice(data);
        //     // file::write_all("/dev/scull_test",&payload)?;

        //     let mut payload = _data.obd2_frame.clone_headers();
        //     payload.try_extend_from_slice(&buffer[..len]);
        //     let device_file = &file::File::create(&CString::new("/dev/scull_test").unwrap(), O_WRONLY)?;
        //     device_file.write_all(&payload)?;

        // }

        pr_info!("File was written\n");
        Ok(reader.len())
    }
}

impl kernel::Module for Scull {
    fn init(_name: &'static CStr, _module: &'static ThisModule) -> Result<Self> {
        pr_info!("Hello world!\n");
        let dev = Arc::try_new(Device::new())?;
        let reg = miscdev::Registration::new_pinned(fmt!("scull_test"), dev)?;
        Ok(Scull{ _dev: reg })
    }
}












impl Obd2Frame {

    fn new_request(
        length: u8,
        mode: u8,
        pid: u8,
        data: Vec<u8>,
      
    ) -> Self {

        Obd2Frame {
            length: length,
            mode: mode,
            pid: pid,
            data: data,
        }
        
    }

    fn clone_headers(&self) -> Vec<u8> {

        let mut payload = Vec::new();
        payload.try_push(self.length);
        payload.try_push(self.mode);
        payload.try_push(self.pid);
        payload

    }
    

    fn get_length(&self) -> u8 {
        self.length
    }

    fn get_mode(&self) -> u8 {
        self.mode
    }

    fn get_pid(&self) -> u8 {
        self.pid
    }

    fn get_data(&self) -> &[u8] {
        &self.data[..]
    }


    fn get_speed(&self) -> u16 {

        let data = self.get_data();
        if data.len() >= 1 {
            (data[0] * 10) as u16
        } else {
            0
        }

    }


    fn get_rpm(&self) -> u32 {
        let data = self.get_data();
        if data.len() >= 2 {
            let a = data[0] as u16;
            let b = data[1] as u16;
            let rpm = (256 * a + b) as u32 / 4;
            rpm
        } else {
            0
        }
    }

   


    fn get_fuel_system_status(&self) -> &str {
        let data = self.get_data();
        if data.len() >= 1 {
            let status = data[0];
            let status_str = match status {
                0x10 => "Fuel System Status: Closed loop, using oxygen sensor feedback for fuel mix",
                0x11 => "Fuel System Status: Open loop, using fixed values for fuel mix",
                0x12 => "Fuel System Status: Closed loop, using oxygen sensor feedback for fuel mix, with valid data from long term fuel trim bank 1",
                0x13 => "Fuel System Status: Closed loop, using oxygen sensor feedback for fuel mix, with valid data from long term fuel trim bank 2",
                0x14 => "Fuel System Status: Closed loop, using oxygen sensor feedback for fuel mix, with valid data from long term fuel trim bank 1 and 2",
                0x15 => "Fuel System Status: Closed loop, using oxygen sensor feedback for fuel mix, with valid data from short term fuel trim bank 1",
                0x16 => "Fuel System Status: Closed loop, using oxygen sensor feedback for fuel mix, with valid data from short term fuel trim bank 2",
                0x17 => "Fuel System Status: Closed loop, using oxygen sensor feedback for fuel mix, with valid data from long term and short term fuel trim bank 1",
                0x18 => "Fuel System Status: Closed loop, using oxygen sensor feedback for fuel mix, with valid data from long term and short term fuel trim bank 2",
                0x19 => "Fuel System Status: Closed loop, using oxygen sensor feedback for fuel mix, with valid data from long term and short term fuel trim bank 1 and 2",
                _ => "Invalid fuel system status",
            };
            status_str
            
        } else {
            "Invalid fuel system status"
        }
    }



  

    fn get_data_dep_pid(&self) -> CString {
        match self.get_pid() {
            //Vehicle Speed
            0x0D => {
                let speed = self.get_speed();
                CString::try_from_fmt(fmt!("Vehicle Speed: {}", speed)).unwrap()
            }

            //RPM
            0x0C => {
                let rpm: u16 = self.get_rpm().try_into().unwrap();
                CString::try_from_fmt(fmt!("RPM: {}", rpm)).unwrap()
            }

            //Fuel System Status
            0x01 => {
                CString::try_from_fmt(fmt!("Fuel System Status: {}", self.get_fuel_system_status())).unwrap()
            }

            //invalid
            _ => {
                pr_info!("Invalid PID.");
                CString::try_from_fmt(fmt!("Invalid PID")).unwrap()
            }
        }
    }


   
    
   

    /*pub fn serialize(&self) -> CString {
       
        let mut serialized_frame = CString::try_from_fmt(fmt!("")).unwrap();

        // Serialize length, mode, and pid        
        for value in [self.length, self.mode, self.pid] {
            serialized_frame.try_push(CString::try_from_fmt(fmt!("{:02x}\n", value)).unwrap());
        }

        // Serialize data
        for &byte in &self.data {
            serialized_frame.try_push(CString::try_from_fmt(fmt!("{:02x}\n", byte)).unwrap());
        }

        serialized_frame
    }*/

    // pub fn serialize(&self) -> CString {
        
    //     let mut serialized_frame2 = CString::try_from_fmt(fmt!("")).unwrap();

    //     // Serialize length, mode, and pid
    //     let serialized_frame1 = CString::try_from_fmt(fmt!("{:02x}{:02x}{:02x}",self.length, self.mode, self.pid)).unwrap();
        
    //     let serialized_frame2 = serialized_frame1;
    //     // Serialize data
    //     for &byte in &self.data {
    //         serialized_frame2 = CString::try_from_fmt(fmt!("{}{:02x}",serialized_frame2, byte)).unwrap();
    //     }

    //     // let mut serialized_frame = CString::try_from_fmt(fmt!("{}{}\n",serialized_frame1,serialized_frame2)).unwrap();
    //     serialized_frame2
        
    // }
        
        
        
    

    // fn serialize(&self) -> CStr {
               
    //     let serialized_frame1 = CStr::from_bytes_with_nul(&[self.length, self.mode, self.pid]).unwrap();
    //     let serialized_frame2 = CStr::from_bytes_with_nul(&self.data).unwrap();
    //     let serialized_frame =  [&serialized_frame1,&serialized_frame2].concat_cstr();
    //     serialized_frame
    // }


    fn concat_cstr<'a>(a: &'a CStr, b: &'a CStr) -> &'a CStr {

        let a_bytes = a.as_bytes();
        let b_bytes = b.as_bytes();
        let mut concat_bytes = Vec::try_with_capacity(a_bytes.len() + b_bytes.len() + 1);
        concat_bytes.expect("REASON").try_extend_from_slice(a_bytes).unwrap();
        //concat_bytes.expect("REASON").try_push(0);
        concat_bytes.expect("REASON").try_extend_from_slice(b_bytes).unwrap();
        CStr::from_bytes_with_nul(&concat_bytes ).unwrap()
    
    }


    fn serialize(&self) -> &CStr {

        let serialized_frame1 = CStr::from_bytes_with_nul(&[self.length, self.mode, self.pid]).unwrap();
        let serialized_frame2 = CStr::from_bytes_with_nul(&self.data).unwrap();
        let serialized_frame = unsafe { CStr::from_bytes_with_nul_unchecked(Obd2Frame::concat_cstr(serialized_frame1,serialized_frame2).as_ref()) };
        serialized_frame
    
    }
    



}

