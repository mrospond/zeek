// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/Inline.h"

#include "zeek/Desc.h"
#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/script_opt/ScriptOpt.h"
#include "zeek/script_opt/StmtOptInfo.h"

namespace zeek::detail {

constexpr int MAX_INLINE_SIZE = 1000;

void Inliner::Analyze() {
    // Locate self- and indirectly recursive functions.

    // Maps each function to any functions that it calls, either
    // directly or (ultimately) indirectly.
    std::unordered_map<const Func*, std::unordered_set<const Func*>> call_set;

    // Prime the call set for each function with the functions it
    // directly calls.
    for ( auto& f : funcs ) {
        std::unordered_set<const Func*> cs;

        // Aspirational ....
        non_recursive_funcs.insert(f.Func());

        for ( auto& func : f.Profile()->ScriptCalls() ) {
            cs.insert(func);

            if ( func == f.Func() ) {
                if ( report_recursive )
                    printf("%s is directly recursive\n", func->Name());

                non_recursive_funcs.erase(func);
            }
        }

        call_set[f.Func()] = cs;
    }

    // Transitive closure.  If we had any self-respect, we'd implement
    // Warshall's algorithm.  What we do here is feasible though since
    // Zeek call graphs tend not to be super-deep.  (We could also save
    // cycles by only analyzing non-[direct-or-indirect] leaves, as
    // was computed by the previous version of this code.  But in
    // practice, the execution time for this is completely dwarfed
    // by the expense of compiling inlined functions, so we keep it
    // simple.)

    // Whether a change has occurred.
    bool did_addition = true;
    while ( did_addition ) {
        did_addition = false;

        // Loop over all the functions of interest.
        for ( auto& c : call_set ) {
            // For each of them, loop over the set of functions
            // they call.

            std::unordered_set<const Func*> addls;

            for ( auto& cc : c.second ) {
                if ( cc == c.first )
                    // Don't loop over ourselves.
                    continue;

                // For each called function, pull up *its*
                // set of called functions.
                for ( auto& ccc : call_set[cc] ) {
                    // For each of those, if we don't
                    // already have it, add it.
                    if ( c.second.count(ccc) > 0 )
                        // We already have it.
                        continue;

                    addls.insert(ccc);

                    if ( ccc != c.first )
                        // Non-recursive.
                        continue;

                    if ( report_recursive )
                        printf("%s is indirectly recursive, called by %s\n", c.first->Name(), cc->Name());

                    non_recursive_funcs.erase(c.first);
                    non_recursive_funcs.erase(cc);
                }
            }

            if ( addls.size() > 0 ) {
                did_addition = true;

                for ( auto& a : addls )
                    c.second.insert(a);
            }
        }
    }

    for ( auto& f : funcs ) {
        if ( f.ShouldSkip() )
            continue;

        const auto& func_ptr = f.FuncPtr();
        const auto& func = func_ptr.get();
        const auto& body = f.Body();

        // Candidates are non-event, non-hook, non-recursive,
        // non-compiled functions ...
        if ( func->Flavor() != FUNC_FLAVOR_FUNCTION )
            continue;

        if ( non_recursive_funcs.count(func) == 0 )
            continue;

        if ( body->Tag() == STMT_CPP )
            continue;

        inline_ables[func] = f.Profile();
    }

    CollapseEventHandlers();

    for ( auto& f : funcs )
        if ( f.ShouldAnalyze() )
            InlineFunction(&f);
}

void Inliner::CollapseEventHandlers() {
    std::unordered_map<ScriptFunc*, size_t> event_handlers;
    BodyInfo body_to_info;
    for ( auto& f : funcs ) {
        if ( ! f.ShouldAnalyze() )
            continue;

        const auto& func_ptr = f.FuncPtr();
        const auto& func = func_ptr.get();
        const auto& func_type = func->GetType();
        const auto& body = f.Body();

        if ( func_type->AsFuncType()->Flavor() != FUNC_FLAVOR_EVENT )
            continue;

        auto& f_attrs = f.Scope()->Attrs();
        if ( f_attrs ) {
            bool is_in_group = false;
            for ( auto& a : *f_attrs )
                if ( a->Tag() == ATTR_GROUP ) {
                    is_in_group = true;
                    break;
                }

            if ( is_in_group )
                continue;
        }

        // Special-case: zeek_init both has tons of event handlers (even
        // with -b), such that it inevitably blows out the inlining budget,
        // *and* only runs once, such that if it takes more time to
        // compile it than to just run it interpreted, it's a lose.
        static std::string zeek_init_name = "zeek_init";
        if ( func->Name() == zeek_init_name )
            continue;

        if ( func->GetKind() == Func::SCRIPT_FUNC && func->GetBodies().size() > 1 ) {
            if ( event_handlers.count(func) == 0 )
                event_handlers[func] = 1;
            else
                ++event_handlers[func];
            ASSERT(body_to_info.count(body.get()) == 0);
            body_to_info.emplace(
                std::pair<const Stmt*, std::reference_wrapper<FuncInfo>>(body.get(),
                                                                         std::reference_wrapper<FuncInfo>(f)));
        }
    }

    for ( auto& e : event_handlers ) {
        auto func = e.first;
        auto& bodies = func->GetBodies();
        if ( bodies.size() != e.second )
            // It's potentially unsound to inline some-but-not-all event
            // handlers, because doing so may violate &priority's. We
            // could do the work of identifying such instances and only
            // skipping those, but given that ZAM is feature-complete
            // the mismatch here should only arise when using restrictions
            // like --optimize-file, which likely aren't the common case.
            continue;

        CollapseEventHandlers({NewRef{}, func}, bodies, body_to_info);
    }
}

void Inliner::CollapseEventHandlers(ScriptFuncPtr func, const std::vector<Func::Body>& bodies,
                                    const BodyInfo& body_to_info) {
    auto merged_body = make_intrusive<StmtList>();
    auto oi = merged_body->GetOptInfo();

    auto& params = func->GetType()->Params();
    auto nparams = params->NumFields();
    size_t init_frame_size = static_cast<size_t>(nparams);
    PreInline(oi, init_frame_size);

    // We use the first body as the primary, which we'll replace (and delete
    // the others) upon success.
    auto& b0 = func->GetBodies()[0].stmts;
    auto b0_info = body_to_info.find(b0.get());
    ASSERT(b0_info != body_to_info.end());
    auto& info0 = b0_info->second.get();
    auto& scope0 = info0.Scope();
    auto& vars = scope0->OrderedVars();

    // We need to create a new Scope. Otherwise, when inlining the first
    // body identifiers get confused regarding whether they represent the
    // outer instance or the inner.
    auto empty_attrs = std::make_unique<std::vector<AttrPtr>>();
    push_scope(scope0->GetID(), std::move(empty_attrs));

    std::vector<IDPtr> param_ids;

    for ( auto i = 0; i < nparams; ++i ) {
        auto& vi = vars[i];
        auto p = install_ID(vi->Name(), "<event>", false, false);
        p->SetType(vi->GetType());
        param_ids.push_back(std::move(p));
    }

    auto new_scope = pop_scope();
    func->SetScope(new_scope);

    // Build up the calling arguments.
    auto args = make_intrusive<ListExpr>();
    for ( auto& p : param_ids )
        args->Append(make_intrusive<NameExpr>(p));

    bool success = true;

    for ( auto& b : bodies ) {
        auto bp = b.stmts;
        auto bi_find = body_to_info.find(bp.get());
        ASSERT(bi_find != body_to_info.end());
        auto& bi = bi_find->second.get();
        auto ie = DoInline(func, bp, args, bi.Scope(), bi.Profile());

        if ( ! ie ) {
            success = false;
            break;
        }

        merged_body->Stmts().push_back(make_intrusive<ExprStmt>(ie));
    }

    if ( success ) {
        PostInline(oi, func);

        info0.SetScope(std::move(new_scope));
        auto pf = std::make_shared<ProfileFunc>(func.get(), merged_body, true);
        info0.SetProfile(std::move(pf));

        // Deactivate script analysis for all of the other bodies.
        for ( auto& b : bodies ) {
            auto bi_find = body_to_info.find(b.stmts.get());
            auto& bi = bi_find->second.get();

            if ( b.stmts == b0 )
                bi.SetBody(merged_body);
            else {
                bi.SetShouldNotAnalyze();
                bi.SetBody(nullptr);
            }
        }

        func->ReplaceBodies(merged_body, func->GetScope(), func->FrameSize());
    }
}

void Inliner::InlineFunction(FuncInfo* f) {
    auto oi = f->Body()->GetOptInfo();
    PreInline(oi, f->Scope()->Length());
    f->Body()->Inline(this);
    PostInline(oi, f->FuncPtr());
}

void Inliner::PreInline(StmtOptInfo* oi, size_t frame_size) {
    max_inlined_frame_size = 0;
    curr_frame_size = frame_size;
    num_stmts = oi->num_stmts;
    num_exprs = oi->num_exprs;
}

void Inliner::PostInline(StmtOptInfo* oi, ScriptFuncPtr f) {
    oi->num_stmts = num_stmts;
    oi->num_exprs = num_exprs;

    int new_frame_size = curr_frame_size + max_inlined_frame_size;

    if ( new_frame_size > f->FrameSize() )
        f->SetFrameSize(new_frame_size);
}

ExprPtr Inliner::CheckForInlining(CallExprPtr c) {
    auto f = c->Func();

    if ( f->Tag() != EXPR_NAME )
        // We don't inline indirect calls.
        return c;

    auto n = f->AsNameExpr();
    auto func = n->Id();

    if ( ! func->IsGlobal() )
        return c;

    const auto& func_v = func->GetVal();
    if ( ! func_v )
        return c;

    auto function = func_v->AsFuncVal()->AsFuncPtr();

    if ( function->GetKind() != Func::SCRIPT_FUNC )
        return c;

    auto func_vf = cast_intrusive<ScriptFunc>(function);

    auto ia = inline_ables.find(func_vf.get());
    if ( ia == inline_ables.end() )
        return c;

    if ( c->IsInWhen() ) {
        // Don't inline these, as doing so requires propagating
        // the in-when attribute to the inlined function body.
        skipped_inlining.insert(func_vf.get());
        return c;
    }

    // Check for mismatches in argument count due to single-arg-of-type-any
    // loophole used for variadic BiFs.  (The issue isn't calls to the
    // BiFs, which won't happen here, but instead to script functions that
    // are misusing/abusing the loophole.)
    if ( function->GetType()->Params()->NumFields() == 1 && c->Args()->Exprs().size() != 1 ) {
        skipped_inlining.insert(func_vf.get());
        return c;
    }

    // We're going to inline the body, unless it's too large.
    auto body = func_vf->GetBodies()[0].stmts; // there's only 1 body
    auto scope = func_vf->GetScope();
    auto ie = DoInline(func_vf, body, c->ArgsPtr(), scope, ia->second);

    if ( ie ) {
        ie->SetOriginal(c);
        did_inline.insert(func_vf.get());
    }

    return ie;
}

ExprPtr Inliner::DoInline(ScriptFuncPtr sf, StmtPtr body, ListExprPtr args, ScopePtr scope, const ProfileFunc* pf) {
    // Inline the body, unless it's too large.
    auto oi = body->GetOptInfo();

    if ( num_stmts + oi->num_stmts + num_exprs + oi->num_exprs > MAX_INLINE_SIZE ) {
        skipped_inlining.insert(sf.get());
        return nullptr; // signals "stop inlining"
    }

    num_stmts += oi->num_stmts;
    num_exprs += oi->num_exprs;

    auto body_dup = body->Duplicate();
    body_dup->GetOptInfo()->num_stmts = oi->num_stmts;
    body_dup->GetOptInfo()->num_exprs = oi->num_exprs;

    // Getting the names of the parameters is tricky.  It's tempting
    // to take them from the function's type declaration, but alas
    // Zeek allows forward-declaring a function with one set of parameter
    // names and then defining a later instance of it with different
    // names, as long as the types match.  So we have to glue together
    // the type declaration, which gives us the number of parameters,
    // with the scope, which gives us all the variables declared in
    // the function, *using the knowledge that the parameters are
    // declared first*.
    auto& vars = scope->OrderedVars();
    int nparam = sf->GetType()->Params()->NumFields();

    std::vector<IDPtr> params;
    std::vector<bool> param_is_modified;

    for ( int i = 0; i < nparam; ++i ) {
        auto& vi = vars[i];
        params.emplace_back(vi);
        param_is_modified.emplace_back((pf->Assignees().count(vi.get()) > 0));
    }

    // Recursively inline the body.  This is safe to do because we've
    // ensured there are no recursive loops ... but we have to be
    // careful in accounting for the frame sizes.
    int frame_size = sf->FrameSize();

    int hold_curr_frame_size = curr_frame_size;
    curr_frame_size = frame_size;

    int hold_max_inlined_frame_size = max_inlined_frame_size;
    max_inlined_frame_size = 0;

    body_dup->Inline(this);

    curr_frame_size = hold_curr_frame_size;

    int new_frame_size = frame_size + max_inlined_frame_size;
    if ( new_frame_size > hold_max_inlined_frame_size )
        max_inlined_frame_size = new_frame_size;
    else
        max_inlined_frame_size = hold_max_inlined_frame_size;

    auto t = scope->GetReturnType();
    // if ( ! t ) t = base_type(TYPE_VOID);

    ASSERT(params.size() == args->Exprs().size());
    auto ie =
        make_intrusive<InlineExpr>(args, std::move(params), std::move(param_is_modified), body_dup, curr_frame_size, t);

    return ie;
}

} // namespace zeek::detail
