// See the file "COPYING" in the main distribution directory for copyright.

// ZAM methods associated with instructions that replace calls to
// built-in functions.

#include "zeek/Func.h"
#include "zeek/Reporter.h"
#include "zeek/script_opt/ZAM/Compile.h"

namespace zeek::detail {

class ZAMBuiltIn {
public:
    virtual ~ZAMBuiltIn() = default;

    bool ReturnValMatters() const { return return_val_matters; }
    bool HaveBothReturnValAndNon() const { return have_both; }

    virtual bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const = 0;

protected:
    bool return_val_matters = true;
    bool have_both = false;
};

class DirectBuiltIn : public ZAMBuiltIn {
public:
    DirectBuiltIn(ZOp _op, int _nargs, bool _return_val_matters = true) : ZAMBuiltIn(), op(_op), nargs(_nargs) {
        return_val_matters = _return_val_matters;
    }

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override {
        ZInstI z;
        if ( nargs == 0 ) {
            if ( n )
                z = ZInstI(op, zam->Frame1Slot(n, OP1_WRITE));
            else
                z = ZInstI(op);
        }
        else {
            ASSERT(nargs == 1);
            auto a0 = zam->FrameSlot(args[0]->AsNameExpr());
            if ( n )
                z = ZInstI(op, zam->Frame1Slot(n, OP1_WRITE), a0);
            else
                z = ZInstI(op, a0);
            z.t = args[0]->GetType();
        }

        zam->AddInst(z);

        return true;
    }

protected:
    ZOp op;
    int nargs;
};

class DirectBuiltInOptAssign : public DirectBuiltIn {
public:
    // First argument is assignment flavor, second is assignment-less flavor.
    DirectBuiltInOptAssign(ZOp _op, ZOp _op2, int _nargs) : DirectBuiltIn(_op, _nargs, false), op2(_op2) {
        have_both = true;
    }

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override {
        if ( n )
            return DirectBuiltIn::Build(zam, n, args);

        ZInstI z;
        if ( nargs == 0 )
            z = ZInstI(op2);
        else {
            ASSERT(nargs == 1);
            auto a0 = zam->FrameSlot(args[0]->AsNameExpr());
            z = ZInstI(op, a0);
            z.t = args[0]->GetType();
        }

        zam->AddInst(z);

        return true;
    }

protected:
    ZOp op2;
};

enum ArgType {
    VV = 0x0,
    VC = 0x1,
    CV = 0x2,
    CC = 0x3,

    VVV = 0x0,
    VVC = 0x1,
    VCV = 0x2,
    VCC = 0x3,
    CVV = 0x4,
    CVC = 0x5,
    CCV = 0x6,
    CCC = 0x7,
};

struct ArgInfo {
    ZOp op;
    ZAMOpType op_type;
};

using BifArgsInfo = std::map<ArgType, ArgInfo>;

class MultiArgBuiltIn : public ZAMBuiltIn {
public:
    MultiArgBuiltIn(bool _return_val_matters, BifArgsInfo _args_info, std::vector<TypeTag> _const_types)
        : ZAMBuiltIn(), args_info(std::move(_args_info)), const_types(std::move(_const_types)) {
        return_val_matters = _return_val_matters;
    }

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override {
        ASSERT(args.size() == const_types.size());

        auto consts = ConstArgsMask(args);
        auto bif_arg_info = args_info.find(consts);
        if ( bif_arg_info == args_info.end() )
            return false;

        std::vector<int> v;
        auto c = args[0]->Tag() == EXPR_CONST ? args[0]->AsConstExpr() : nullptr;

        for ( auto i = 0U; i < args.size(); ++i ) {
            auto a = args[i];

            if ( a->Tag() == EXPR_NAME )
                v.push_back(zam->FrameSlot(a->AsNameExpr()));
            else if ( i == 0 && c )
                v.push_back(0);
            else {
                ASSERT(i < const_types.size());
                auto t = const_types[i];
                ASSERT(t == TYPE_INT || t == TYPE_COUNT);

                int slot_val;
                if ( t == TYPE_INT )
                    slot_val = a->AsConstExpr()->Value()->AsInt();
                else
                    slot_val = static_cast<int>(a->AsConstExpr()->Value()->AsCount());
                v.push_back(slot_val);
            }
        }

        auto nslot = n ? zam->Frame1Slot(n, OP1_WRITE) : -1;

        ZInstI z;
        const auto& bi = bif_arg_info->second;
        auto op = bi.op;

        if ( args.size() == 3 ) {
            switch ( consts ) {
                case VVV:
                case VVC:
                case VCC: break;

                case VCV: std::swap(v[2], v[1]); break;

                case CCV:
                    std::swap(v[2], v[1]);
                    // fall through
                case CVV:
                case CVC:
                case CCC: v.erase(v.begin()); break;
            }

            if ( n ) {
                if ( c )
                    z = ZInstI(op, nslot, v[0], v[1], c);
                else
                    z = ZInstI(op, nslot, v[0], v[1], v[2]);
            }
            else {
                if ( c )
                    z = ZInstI(op, v[0], v[1], c);
                else
                    z = ZInstI(op, v[0], v[1], v[2]);
            }
        }

        z.op_type = bi.op_type;

        zam->AddInst(z);

        return true;
    }

private:
    // Returns a bit mask of which of the arguments in the given list
    // correspond to constants, with the high-ordered bit being the first
    // argument (argument "0" in the list) and the low-ordered bit being
    // the last. These correspond to the ArgType enum integer values.
    ArgType ConstArgsMask(const ExprPList& args) const {
        zeek_uint_t mask = 0;

        for ( int i = 0; i < args.size(); ++i ) {
            mask <<= 1;
            if ( args[i]->Tag() == EXPR_CONST )
                mask |= 1;
        }

        return ArgType(mask);
    }

    BifArgsInfo args_info;
    std::vector<TypeTag> const_types;
};

class SortBiF : public DirectBuiltIn {
public:
    SortBiF() : DirectBuiltIn(OP_SORT_V, 1, false) {}

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override {
        if ( args.size() > 2 )
            return false;

        auto v = args[0]->AsNameExpr();
        if ( v->GetType()->Tag() != TYPE_VECTOR )
            return false;

        const auto& elt_type = v->GetType()->Yield();

        if ( args.size() == 1 ) {
            if ( ! IsIntegral(elt_type->Tag()) && elt_type->InternalType() != TYPE_INTERNAL_DOUBLE )
                return false;

            return DirectBuiltIn::Build(zam, n, args);
        }

        const auto& comp_val = args[1];
        if ( ! IsFunc(comp_val->GetType()->Tag()) )
            return false;

        if ( comp_val->Tag() != EXPR_NAME )
            return false;

        auto comp_func_val = comp_val->AsNameExpr()->Id()->GetVal();
        if ( ! comp_func_val )
            return false;

        auto comp = comp_func_val->AsFunc();
        const auto& comp_type = comp->GetType();

        if ( comp_type->Yield()->Tag() != TYPE_INT || ! comp_type->ParamList()->AllMatch(elt_type, 0) ||
             comp_type->ParamList()->GetTypes().size() != 2 )
            return false;

        zam->AddInst(ZInstI(OP_SORT_WITH_CMP_VV, zam->FrameSlot(v), zam->FrameSlot(comp_val->AsNameExpr())));

        return true;
    }
};

class CatBiF : public ZAMBuiltIn {
public:
    CatBiF() : ZAMBuiltIn() {}

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override {
        auto nslot = zam->Frame1Slot(n, OP1_WRITE);
        auto& a0 = args[0];
        ZInstI z;

        if ( args.empty() ) {
            // Weird, but easy enough to support.
            z = ZInstI(OP_CAT1_VC, nslot);
            z.t = n->GetType();
            z.c = ZVal(val_mgr->EmptyString());
        }

        else if ( args.size() > 1 ) {
            switch ( args.size() ) {
                case 2: z = zam->GenInst(OP_CAT2_V, n); break;
                case 3: z = zam->GenInst(OP_CAT3_V, n); break;
                case 4: z = zam->GenInst(OP_CAT4_V, n); break;
                case 5: z = zam->GenInst(OP_CAT5_V, n); break;
                case 6: z = zam->GenInst(OP_CAT6_V, n); break;
                case 7: z = zam->GenInst(OP_CAT7_V, n); break;
                case 8: z = zam->GenInst(OP_CAT8_V, n); break;

                default: z = zam->GenInst(OP_CATN_V, n); break;
            }

            z.aux = BuildCatAux(zam, args);
        }

        else if ( a0->GetType()->Tag() != TYPE_STRING ) {
            if ( a0->Tag() == EXPR_NAME ) {
                z = zam->GenInst(OP_CAT1FULL_VV, n, a0->AsNameExpr());
                z.t = a0->GetType();
            }
            else {
                z = ZInstI(OP_CAT1_VC, nslot);
                z.t = n->GetType();
                z.c = ZVal(ZAM_val_cat(a0->AsConstExpr()->ValuePtr()));
            }
        }

        else if ( a0->Tag() == EXPR_CONST ) {
            z = zam->GenInst(OP_CAT1_VC, n, a0->AsConstExpr());
            z.t = n->GetType();
        }

        else
            z = zam->GenInst(OP_CAT1_VV, n, a0->AsNameExpr());

        zam->AddInst(z);

        return true;
    }

private:
    ZInstAux* BuildCatAux(ZAMCompiler* zam, const ExprPList& args) const {
        auto n = args.size();
        auto aux = new ZInstAux(n);
        aux->cat_args = new std::unique_ptr<CatArg>[n];

        for ( size_t i = 0; i < n; ++i ) {
            auto& a_i = args[i];
            auto& t = a_i->GetType();

            std::unique_ptr<CatArg> ca;

            if ( a_i->Tag() == EXPR_CONST ) {
                auto c = a_i->AsConstExpr()->ValuePtr();
                aux->Add(i, c); // it will be ignored
                auto sv = ZAM_val_cat(c);
                auto s = sv->AsString();
                auto b = reinterpret_cast<char*>(s->Bytes());
                ca = std::make_unique<CatArg>(std::string(b, s->Len()));
            }

            else {
                auto slot = zam->FrameSlot(a_i->AsNameExpr());
                aux->Add(i, slot, t);

                switch ( t->Tag() ) {
                    case TYPE_BOOL:
                    case TYPE_INT:
                    case TYPE_COUNT:
                    case TYPE_DOUBLE:
                    case TYPE_TIME:
                    case TYPE_ENUM:
                    case TYPE_PORT:
                    case TYPE_ADDR:
                    case TYPE_SUBNET: ca = std::make_unique<FixedCatArg>(t); break;

                    case TYPE_STRING: ca = std::make_unique<StringCatArg>(); break;

                    case TYPE_PATTERN: ca = std::make_unique<PatternCatArg>(); break;

                    default: ca = std::make_unique<DescCatArg>(t); break;
                }
            }

            aux->cat_args[i] = std::move(ca);
        }

        return aux;
    }
};

class FilesSetReassemBiF : public ZAMBuiltIn {
public:
    FilesSetReassemBiF() : ZAMBuiltIn() { return_val_matters = false; }

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override {
        if ( args[0]->Tag() == EXPR_CONST )
            // Weird!
            return false;

        ZInstI z;

        auto arg0_slot = zam->FrameSlot(args[0]->AsNameExpr());

        if ( args[1]->Tag() == EXPR_NAME ) {
            auto arg1_slot = zam->FrameSlot(args[1]->AsNameExpr());
            z = ZInstI(OP_FILES_SET_REASSEMBLY_BUFFER_VV, arg0_slot, arg1_slot);
        }

        else {
            auto arg_cnt = args[1]->AsConstExpr()->Value()->AsCount();
            z = ZInstI(OP_FILES_SET_REASSEMBLY_BUFFER_VC, arg0_slot, arg_cnt);
            z.op_type = OP_VV_I2;
        }

        zam->AddInst(z);

        return true;
    }
};

class LogWriteBiF : public ZAMBuiltIn {
public:
    LogWriteBiF() : ZAMBuiltIn() { return_val_matters = false; }

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override {
        auto id = args[0];
        auto columns = args[1];

        if ( columns->Tag() != EXPR_NAME )
            return false;

        auto columns_n = columns->AsNameExpr();
        auto col_slot = zam->FrameSlot(columns_n);

        bool const_id = (id->Tag() == EXPR_CONST);

        ZInstAux* aux = nullptr;

        if ( const_id ) {
            aux = new ZInstAux(1);
            aux->Add(0, id->AsConstExpr()->ValuePtr());
        }

        ZInstI z;

        if ( n ) {
            auto nslot = zam->Frame1Slot(n, OP1_WRITE);

            if ( const_id ) {
                z = ZInstI(OP_LOG_WRITEC_VV, nslot, col_slot);
                z.aux = aux;
            }
            else
                z = ZInstI(OP_LOG_WRITE_VVV, nslot, zam->FrameSlot(id->AsNameExpr()), col_slot);
        }
        else {
            if ( const_id ) {
                z = ZInstI(OP_LOG_WRITEC_V, col_slot, id->AsConstExpr());
                z.aux = aux;
            }
            else
                z = ZInstI(OP_LOG_WRITE_VV, zam->FrameSlot(id->AsNameExpr()), col_slot);
        }

        z.SetType(columns_n->GetType());

        zam->AddInst(z);

        return true;
    }
};

class SetConnBytesThreshBiF : public ZAMBuiltIn {
public:
    SetConnBytesThreshBiF() : ZAMBuiltIn() {}

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override { return true; }
};

class StrStrBiF : public ZAMBuiltIn {
public:
    StrStrBiF() : ZAMBuiltIn() {}

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override {
        auto big = args[0];
        auto little = args[1];

        auto big_n = big->Tag() == EXPR_NAME ? big->AsNameExpr() : nullptr;
        auto little_n = little->Tag() == EXPR_NAME ? little->AsNameExpr() : nullptr;

        ZInstI z;

        if ( big_n && little_n )
            z = zam->GenInst(OP_STRSTR_VVV, n, big_n, little_n);
        else if ( big_n )
            z = zam->GenInst(OP_STRSTR_VVC, n, big_n, little->AsConstExpr());
        else if ( little_n )
            z = zam->GenInst(OP_STRSTR_VCV, n, little_n, big->AsConstExpr());
        else
            return false;

        zam->AddInst(z);

        return true;
    }
};

bool ZAMCompiler::IsZAM_BuiltIn(const Expr* e) {
    // The expression e is either directly a call (in which case there's
    // no return value), or an assignment to a call.
    const CallExpr* c;

    if ( e->Tag() == EXPR_CALL )
        c = e->AsCallExpr();
    else
        c = e->GetOp2()->AsCallExpr();

    auto func_expr = c->Func();
    if ( func_expr->Tag() != EXPR_NAME )
        // An indirect call.
        return false;

    auto func_val = func_expr->AsNameExpr()->Id()->GetVal();
    if ( ! func_val )
        // A call to a function that hasn't been defined.
        return false;

    auto func = func_val->AsFunc();
    if ( func->GetKind() != BuiltinFunc::BUILTIN_FUNC )
        return false;

    static auto sub_bytes_consts = std::vector<TypeTag>{TYPE_STRING, TYPE_COUNT, TYPE_INT};

    static BifArgsInfo sub_bytes_info;

    static bool did_init = false;
    if ( ! did_init ) {
        // We initialize these explicitly rather than with initializer
        // lists just because the latter gets hard to read.
        sub_bytes_info[VVV] = {OP_SUB_BYTES_VVVV, OP_VVVV};
        sub_bytes_info[VVC] = {OP_SUB_BYTES_VVVi, OP_VVVV_I4};
        sub_bytes_info[VCV] = {OP_SUB_BYTES_VViV, OP_VVVV_I4};
        sub_bytes_info[VCC] = {OP_SUB_BYTES_VVii, OP_VVVV_I3_I4};
        sub_bytes_info[CVV] = {OP_SUB_BYTES_VVVC, OP_VVVC};
        sub_bytes_info[CVC] = {OP_SUB_BYTES_VViC, OP_VVVC_I3};
        sub_bytes_info[CCV] = {OP_SUB_BYTES_ViVC, OP_VVVC_I3};
        sub_bytes_info[CCC] = {OP_SUB_BYTES_ViiC, OP_VVVC_I2_I3};

        did_init = true;
    }

    static std::map<std::string, std::shared_ptr<ZAMBuiltIn>> builtins = {
        {"Analyzer::__name", std::make_shared<DirectBuiltIn>(OP_ANALYZER_NAME_VV, 1)},
        {"Broker::__flush_logs",
         std::make_shared<DirectBuiltInOptAssign>(OP_BROKER_FLUSH_LOGS_V, OP_BROKER_FLUSH_LOGS_X, 0)},
        {"Files::__enable_reassembly", std::make_shared<DirectBuiltIn>(OP_FILES_ENABLE_REASSEMBLY_V, 1, false)},
        {"Files::__set_reassembly_buffer", std::make_shared<FilesSetReassemBiF>()},
        {"Log::__write", std::make_shared<LogWriteBiF>()},
        {"cat", std::make_shared<CatBiF>()},
        {"current_time", std::make_shared<DirectBuiltIn>(OP_CURRENT_TIME_V, 0)},
        {"get_port_transport_proto", std::make_shared<DirectBuiltIn>(OP_GET_PORT_TRANSPORT_PROTO_VV, 1)},
        {"is_v4_addr", std::make_shared<DirectBuiltIn>(OP_IS_V4_ADDR_VV, 1)},
        {"is_v6_addr", std::make_shared<DirectBuiltIn>(OP_IS_V6_ADDR_VV, 1)},
        {"network_time", std::make_shared<DirectBuiltIn>(OP_NETWORK_TIME_V, 0)},
        {"reading_live_traffic", std::make_shared<DirectBuiltIn>(OP_READING_LIVE_TRAFFIC_V, 0)},
        {"reading_traces", std::make_shared<DirectBuiltIn>(OP_READING_TRACES_V, 0)},
        {"set_current_conn_bytes_threshold", std::make_shared<SetConnBytesThreshBiF>()},
        {"sort", std::make_shared<SortBiF>()},
        {"strstr", std::make_shared<StrStrBiF>()},
        {"sub_bytes", std::make_shared<MultiArgBuiltIn>(true, sub_bytes_info, sub_bytes_consts)},
        {"to_lower", std::make_shared<DirectBuiltIn>(OP_TO_LOWER_VV, 1)},
    };

    auto b = builtins.find(func->Name());
    if ( b == builtins.end() )
        return false;

    const auto& bi = b->second;

    const NameExpr* n = nullptr; // name to assign to, if any
    if ( e->Tag() != EXPR_CALL )
        n = e->GetOp1()->AsRefExpr()->GetOp1()->AsNameExpr();

    if ( bi->ReturnValMatters() ) {
        if ( ! n ) {
            reporter->Warning("return value from built-in function ignored");

            // The call is a no-op. We could return false here and have it
            // execute (for no purpose). We can also return true, which will
            // have the effect of just ignoring the statement.
            return true;
        }
    }
    else if ( n && ! bi->HaveBothReturnValAndNon() ) {
        // Because the return value "doesn't matter", we've built the
        // BiF replacement operation assuming we don't need a version that
        // does the assignment. If we *do* have an assignment, let the usual
        // call take its place.
        return false;
    }

    return bi->Build(this, n, c->Args()->Exprs());
}

} // namespace zeek::detail
