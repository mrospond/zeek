// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/Manager.h"

namespace zeek::storage {

Manager::Manager() : plugin::ComponentManager<storage::Component>("Storage", "Backend") {}

void Manager::InitPostScript() { detail::backend_opaque = make_intrusive<OpaqueType>("Storage::Backend"); }

/**
 * Opens a new storage backend.
 *
 * @param type The tag for the type of backend being opened.
 * @param configuration A record val representing the configuration for this
 * type of backend.
 * @return A pointer to a backend instance.
 */
BackendPtr Manager::OpenBackend(const Tag& type, RecordValPtr config, TypePtr vt) {
    Component* c = Lookup(type);
    if ( ! c ) {
        reporter->InternalWarning("Request to open unknown backend");
        return nullptr;
    }

    if ( ! c->Factory() ) {
        reporter->InternalWarning("Backend %s cannot be instantiated dynamically ", GetComponentName(type).c_str());
        return nullptr;
    }

    Backend* b = c->Factory()();

    if ( ! b ) {
        reporter->InternalWarning("Failed to instantiate backend %s\n", GetComponentName(type).c_str());
        return nullptr;
    }

    if ( ! b->Open(std::move(config), std::move(vt)) ) {
        reporter->InternalWarning("Failed to open backend %s\n", GetComponentName(type).c_str());
        delete b;
        return nullptr;
    }

    return IntrusivePtr<Backend>{AdoptRef{}, b};
}

} // namespace zeek::storage
