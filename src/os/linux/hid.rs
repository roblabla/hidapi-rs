use std::convert::TryInto;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HidTy {
    Main(HidMain),
    Global(HidGlobal),
    Local(HidLocal),
    LongItem,
    Reserved(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HidMain {
    Input,
    Output,
    Feature,
    Collection,
    EndCollection,
    Reserved(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HidGlobal {
    UsagePage,
    LogicalMinimum,
    LogicalMaximum,
    PhysicalMinimum,
    PhysicalMaximum,
    UnitExponent,
    Unit,
    ReportSize,
    ReportId,
    ReportCount,
    Push,
    Pop,
    Reserved(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HidLocal {
    Usage,
    UsageMinimum,
    UsageMaximum,
    DesignatorIndex,
    DesignatorMinimum,
    DesignatorMaximum,
    StringIndex,
    StringMinimum,
    StringMaximum,
    Delimiter,
    Reserved(u8),
}

bitfield::bitfield! {
    pub struct HidItemType(u8);
    impl Debug;
    get_size, _: 1, 0;
    get_ty, _: 3, 2;
    get_tag, _: 7, 4;
}

impl HidItemType {
    pub fn size(&self) -> usize {
        match self.get_size() {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 4,
            _ => unreachable!(),
        }
    }

    pub fn ty(&self) -> HidTy {
        let ty = self.get_ty();
        let tag = self.get_tag();

        match (ty, tag) {
            // Parse tags from
            (0, 0b1000) => HidTy::Main(HidMain::Input),
            (0, 0b1001) => HidTy::Main(HidMain::Output),
            (0, 0b1011) => HidTy::Main(HidMain::Feature),
            (0, 0b1010) => HidTy::Main(HidMain::Collection),
            (0, 0b1100) => HidTy::Main(HidMain::EndCollection),
            (0, tag) => HidTy::Main(HidMain::Reserved(tag)),
            (1, 0b0000) => HidTy::Global(HidGlobal::UsagePage),
            (1, 0b0001) => HidTy::Global(HidGlobal::LogicalMinimum),
            (1, 0b0010) => HidTy::Global(HidGlobal::LogicalMaximum),
            (1, 0b0011) => HidTy::Global(HidGlobal::PhysicalMinimum),
            (1, 0b0100) => HidTy::Global(HidGlobal::PhysicalMaximum),
            (1, 0b0101) => HidTy::Global(HidGlobal::UnitExponent),
            (1, 0b0110) => HidTy::Global(HidGlobal::Unit),
            (1, 0b0111) => HidTy::Global(HidGlobal::ReportSize),
            (1, 0b1000) => HidTy::Global(HidGlobal::ReportId),
            (1, 0b1001) => HidTy::Global(HidGlobal::ReportCount),
            (1, 0b1010) => HidTy::Global(HidGlobal::Push),
            (1, 0b1011) => HidTy::Global(HidGlobal::Pop),
            (1, tag) => HidTy::Global(HidGlobal::Reserved(tag)),
            (2, 0b0000) => HidTy::Local(HidLocal::Usage),
            (2, 0b0001) => HidTy::Local(HidLocal::UsageMinimum),
            (2, 0b0010) => HidTy::Local(HidLocal::UsageMaximum),
            (2, 0b0011) => HidTy::Local(HidLocal::DesignatorIndex),
            (2, 0b0100) => HidTy::Local(HidLocal::DesignatorMinimum),
            (2, 0b0101) => HidTy::Local(HidLocal::DesignatorMaximum),
            (2, 0b0111) => HidTy::Local(HidLocal::StringIndex),
            (2, 0b1000) => HidTy::Local(HidLocal::StringMinimum),
            (2, 0b1001) => HidTy::Local(HidLocal::StringMaximum),
            (2, 0b1010) => HidTy::Local(HidLocal::Delimiter),
            (2, tag) => HidTy::Local(HidLocal::Reserved(tag)),
            (3, 0b1111) => HidTy::LongItem,
            (3, tag) => HidTy::Reserved(tag),
            _ => unreachable!(),
        }
    }
}

pub enum HidItem {
    SmallItem(u32),
    LongItem(Vec<u8>)
}

pub struct HidItemIterator<T> {
    desc: T,
    pos: usize,
}

impl<T> Iterator for HidItemIterator<T>
where
    T: AsRef<[u8]>
{
    type Item = (HidTy, HidItem);
    fn next(&mut self) -> Option<(HidTy, HidItem)> {
        let desc = &self.desc.as_ref()[self.pos..];
        let key = HidItemType(*desc.get(0)?);
        let size = key.size();
        let ty = key.ty();
        if key.ty() == HidTy::LongItem {
            let data_size = *desc.get(1)? as usize;
            let _long_ty = *desc.get(2)?;
            let item_data = desc.get(3..3 + data_size)?;
            self.pos += 3 + data_size;
            Some((ty, HidItem::LongItem(item_data.to_vec())))
        } else {
            let data = match size {
                0 => 0,
                1 => u32::from(*desc.get(1)?),
                2 => u32::from(u16::from_le_bytes(desc.get(1..=2)?.try_into().unwrap())),
                4 => u32::from_le_bytes(desc.get(1..=4)?.try_into().unwrap()),
                _ => unreachable!(),
            };
            self.pos += 1 + size;
            Some((ty, HidItem::SmallItem(data)))
        }
    }
}

pub fn iterate_hid_descriptor<T>(desc: T) -> HidItemIterator<T> {
    HidItemIterator {
        desc,
        pos: 0,
    }
}