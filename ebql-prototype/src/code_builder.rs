use std::marker::PhantomData;

// Common characters
const NL: u8 = '\n' as u8;
const NLNL: [u8; 2] = [NL; 2];
const TAB: u8 = '\t' as u8;

// Common variable modifications
pub const CONST: &str = "const";
pub const VOLATILE: &str = "volatile";
pub const STATIC: &str = "static";
pub const ALWAYS_INLINE: &str = "__always_inline";

// Common map attributes
pub const __UINT: &str = "__uint";
pub const __TYPE: &str = "__type";

// Map types
pub const RINGBUF: &str = "BPF_MAP_TYPE_RINGBUF";
pub const HASHMAP: &str = "BPF_MAP_TYPE_HASH";

// Map attribute keys
pub const TYPE: &str = "type";
pub const MAX_ENTRIES: &str = "max_entries";

// Initial capacity for builder buffers
const INITIAL_CAPACITY: usize = 1 << 12;

// Default license for most BPF programs
const DEFAULT_LICENSE: &str = r#"char LICENSE[] SEC("license") = "Dual BSD/GPL";"#;

// Code builder for BPF programs.
pub struct BpfCodeBuilder<S = Base> {
    prefix: Vec<u8>,

    // buffers for different code components:
    // - includes_buf contains include definitions
    // - defs_buf contains definitions (e.g. structs, maps, typedefs)
    // - globals_buf contains global definitions (i.e. bss and rodata, so including consts)
    // - code_buf contains actual code (i.e. functions)
    includes_buf: Vec<u8>,
    defs_buf: Vec<u8>,
    globals_buf: Vec<u8>,
    code_buf: Vec<u8>,

    // type marker to ensure type safety when constructing things
    _marker: PhantomData<S>,
}

impl BpfCodeBuilder<Base> {
    pub fn new() -> Self {
        Self {
            prefix: Vec::new(),
            includes_buf: Vec::new(),
            defs_buf: Vec::new(),
            globals_buf: Vec::new(),
            code_buf: Vec::new(),
            _marker: PhantomData,
        }
    }

    // Adds an includes header directive. Specify whether the header file is a
    // system or project file.
    pub fn write_includes(
        &mut self,
        header: &str,
        system: bool,
        comment: Option<&str>,
    ) -> &mut Self {
        let (open, close) = if system { ('<', '>') } else { ('"', '"') };
        let str = format!(
            "#include {}{}{} /* {} */",
            open,
            header,
            close,
            comment.unwrap_or_default()
        );
        self.includes_buf.extend(str.as_bytes());
        self.includes_buf.push(NL);
        self
    }

    // Writes a global expression.
    pub fn write_global(
        &mut self,
        mods: Vec<&str>,
        expr_type: &str,
        expr: &str,
        value: Option<&str>,
    ) -> &mut Self {
        let mods = mods.join(" ");
        let assignment = match value {
            Some(value) => format!(" = {}", value),
            None => String::new(),
        };
        let str = format!("{} {} {}{};", mods, expr_type, expr, assignment);
        self.globals_buf.extend(str.as_bytes());
        self.globals_buf.push(NL);
        self
    }

    // Starts a struct definition. The user must close the struct definition using
    // self.close().
    pub fn write_struct(mut self, name: &str) -> BpfCodeBuilder<StructConstruction> {
        let str = format!("{} {{", name);
        self.defs_buf.extend(str.as_bytes());
        self.defs_buf.push(NL);

        // Convert into different type
        self.prefix.push(TAB);
        BpfCodeBuilder::<StructConstruction> {
            _marker: PhantomData,
            ..self.into()
        }
    }

    // Starts a map definition. The user must close the map definition using
    // self.close().
    pub fn write_map(mut self) -> BpfCodeBuilder<MapConstruction> {
        let bytes = "struct {".as_bytes();
        self.defs_buf.extend(bytes);
        self.defs_buf.push(NL);

        // Convert into different type
        self.prefix.push(TAB);
        BpfCodeBuilder::<MapConstruction> {
            _marker: PhantomData,
            ..self.into()
        }
    }

    pub fn write_function(
        mut self,
        section: &str,
        return_type: &str,
        name: &str,
        args: &[Arg],
    ) -> BpfCodeBuilder<BodyConstruction> {
        // Construct function header
        let mut str = format!(r#"SEC("{}")"#, section);
        str.push(NL as char);
        str.push_str(&format!("{} {}(", return_type, name));
        for (i, arg) in args.iter().enumerate() {
            str.push_str(&format!("{} {}", arg._type, arg._name));
            if i != args.len() - 1 {
                str.push(',');
            }
        }
        str.push_str(") {");
        let bytes = str.as_bytes();

        // Add to buffer
        self.code_buf.extend(bytes);
        self.code_buf.push(NL);

        // Convert into different type
        self.prefix.push(TAB);
        BpfCodeBuilder::<BodyConstruction> {
            _marker: PhantomData,
            ..self.into()
        }
    }

    pub fn build(self) -> String {
        // Combine separate sections into one string
        let cap = self.includes_buf.len()
            + self.defs_buf.len()
            + self.globals_buf.len()
            + self.code_buf.len();
        let mut out = Vec::with_capacity(cap);

        out.extend("// *** INCLUDES SECTION *** //".as_bytes());
        out.push(NL);
        out.extend(self.includes_buf);
        out.extend(NLNL);

        out.extend("// *** DEFINITIONS SECTION *** //".as_bytes());
        out.push(NL);
        out.extend(self.defs_buf);
        out.extend(NLNL);

        out.extend("// *** GLOBALS SECTION *** //".as_bytes());
        out.push(NL);
        out.extend(self.globals_buf);
        out.extend(NLNL);

        out.extend("// *** CODE SECTION *** //".as_bytes());
        out.push(NL);
        out.extend(self.code_buf);
        out.extend(NLNL);

        out.extend("// *** LICENSE *** //".as_bytes());
        out.push(NL);
        out.extend(DEFAULT_LICENSE.as_bytes());
        out.push(NL);

        String::from_utf8(out).unwrap()
    }
}

impl BpfCodeBuilder<StructConstruction> {
    pub fn write_field(&mut self, field: &str, field_type: &str) -> &mut Self {
        let str = format!("{} {};", field_type, field);
        self.defs_buf.extend(&self.prefix);
        self.defs_buf.extend(str.as_bytes());
        self.defs_buf.push(NL);

        self
    }

    pub fn close(mut self) -> BpfCodeBuilder<Base> {
        self.defs_buf
            .extend("} __attribute__((packed));".as_bytes());
        // .extend("};".as_bytes());
        self.defs_buf.push(NL);

        self.prefix.pop();
        BpfCodeBuilder::<Base> {
            _marker: PhantomData,
            ..self.into()
        }
    }
}

impl BpfCodeBuilder<MapConstruction> {
    pub fn write_attr(&mut self, attr: &str, key: &str, val: &str) -> &mut Self {
        let str = format!("{}({}, {});", attr, key, val);
        self.defs_buf.extend(&self.prefix);
        self.defs_buf.extend(str.as_bytes());
        self.defs_buf.push(NL);

        self
    }

    pub fn close(mut self, name: &str) -> BpfCodeBuilder<Base> {
        let str = format!(r#"}} {} SEC(".maps");"#, name);
        self.defs_buf.extend(str.as_bytes());
        self.defs_buf.push(NL);

        self.prefix.pop();
        BpfCodeBuilder::<Base> {
            _marker: PhantomData,
            ..self.into()
        }
    }
}

impl BpfCodeBuilder<BodyConstruction> {
    pub fn write_var_initialization(
        &mut self,
        expr: &str,
        expr_type: &str,
        expr_value: &str,
    ) -> &mut Self {
        let str = format!("{} {} = {};", expr_type, expr, expr_value);
        self.code_buf.extend(&self.prefix);
        self.code_buf.extend(str.as_bytes());
        self.code_buf.push(NL);
        self
    }

    pub fn write_var_assignment(&mut self, expr: &str, expr_value: &str) -> &mut Self {
        let str = format!("{} = {};", expr, expr_value);
        self.code_buf.extend(&self.prefix);
        self.code_buf.extend(str.as_bytes());
        self.code_buf.push(NL);
        self
    }

    pub fn write_func_call(&mut self, func: &str, args: &[&str]) -> &mut Self {
        let mut str = format!("{}(", func);
        for (i, arg) in args.iter().enumerate() {
            str.push_str(&format!("{}", arg));
            if i != args.len() - 1 {
                str.push(',');
            }
        }
        str = str + ");";
        self.code_buf.extend(&self.prefix);
        self.code_buf.extend(str.as_bytes());
        self.code_buf.push(NL);
        self
    }

    pub fn write_if(&mut self, cond: &str) -> &mut Self {
        let str = format!("if ({}) {{", cond);
        self.code_buf.extend(&self.prefix);
        self.code_buf.extend(str.as_bytes());

        self.prefix.push(NL);
        self
    }

    pub fn close_if(&mut self) -> &mut Self {
        self.prefix.pop();

        self.code_buf.extend(&self.prefix);
        self.code_buf.push('}' as u8);
        self.code_buf.push(NL);
        self
    }

    pub fn write_return(&mut self, val: &str) -> &mut Self {
        let str = format!("return {};", val);
        self.code_buf.extend(&self.prefix);
        self.code_buf.extend(str.as_bytes());
        self.code_buf.push(NL);
        self
    }

    pub fn close(mut self) -> BpfCodeBuilder<Base> {
        self.code_buf.push('}' as u8);
        self.code_buf.push(NL);
        self.prefix.pop();
        BpfCodeBuilder::<Base> {
            _marker: PhantomData,
            ..self.into()
        }
    }
}

// State transitions
#[derive(Clone, Copy, Debug, Default)]
pub struct Base;
#[derive(Clone, Copy, Debug)]
pub struct StructConstruction;
#[derive(Clone, Copy, Debug)]
pub struct MapConstruction;
#[derive(Clone, Copy, Debug)]
pub struct BodyConstruction;

#[derive(Clone)]
pub struct Arg {
    pub _name: String,
    pub _type: String,
}

pub struct Includes {
    pub file: String,
    pub is_system: bool,
    pub comment: Option<String>,
}
