export namespace catalog {
	
	export class Custom {
	    host: string;
	    group: string;
	
	    static createFrom(source: any = {}) {
	        return new Custom(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.host = source["host"];
	        this.group = source["group"];
	    }
	}
	export class Item {
	    id: string;
	    host: string;
	    group: string;
	    name: string;
	    note: string;
	
	    static createFrom(source: any = {}) {
	        return new Item(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.host = source["host"];
	        this.group = source["group"];
	        this.name = source["name"];
	        this.note = source["note"];
	    }
	}

}

export namespace config {
	
	export class Targets {
	    Runet: string[];
	    Global: string[];
	    Blocked: string[];
	    GeoBlocked: string[];
	
	    static createFrom(source: any = {}) {
	        return new Targets(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Runet = source["Runet"];
	        this.Global = source["Global"];
	        this.Blocked = source["Blocked"];
	        this.GeoBlocked = source["GeoBlocked"];
	    }
	}
	export class Selection {
	    Enabled: string[];
	    Custom: catalog.Custom[];
	
	    static createFrom(source: any = {}) {
	        return new Selection(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Enabled = source["Enabled"];
	        this.Custom = this.convertValues(source["Custom"], catalog.Custom);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class UI {
	    FontHUD: string;
	    FontMono: string;
	    FontFile: string;
	    Scale: string;
	    Tab: string;
	
	    static createFrom(source: any = {}) {
	        return new UI(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.FontHUD = source["FontHUD"];
	        this.FontMono = source["FontMono"];
	        this.FontFile = source["FontFile"];
	        this.Scale = source["Scale"];
	        this.Tab = source["Tab"];
	    }
	}
	export class Config {
	    Lang: string;
	    UI: UI;
	    Services: Selection;
	    Targets: Targets;
	    // Go type: struct { Gateway bool "yaml:\"gateway\""; GlobalIP string "yaml:\"global_ip\"" }
	    Ping: any;
	    ProxyPorts: number[];
	    // Go type: struct { Enabled bool "yaml:\"enabled\""; Style string "yaml:\"style\""; Spin bool "yaml:\"spin\""; GeoLookup bool "yaml:\"geo_lookup\"" }
	    Map: any;
	    // Go type: struct { ProbeMs int "yaml:\"probe_ms\""; RunMs int "yaml:\"run_ms\"" }
	    Timeouts: any;
	    HistoryKeep: number;
	
	    static createFrom(source: any = {}) {
	        return new Config(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Lang = source["Lang"];
	        this.UI = this.convertValues(source["UI"], UI);
	        this.Services = this.convertValues(source["Services"], Selection);
	        this.Targets = this.convertValues(source["Targets"], Targets);
	        this.Ping = this.convertValues(source["Ping"], Object);
	        this.ProxyPorts = source["ProxyPorts"];
	        this.Map = this.convertValues(source["Map"], Object);
	        this.Timeouts = this.convertValues(source["Timeouts"], Object);
	        this.HistoryKeep = source["HistoryKeep"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	

}

export namespace env {
	
	export class ProxyHint {
	    kind: string;
	    proto: string;
	    addr: string;
	    active: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ProxyHint(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.kind = source["kind"];
	        this.proto = source["proto"];
	        this.addr = source["addr"];
	        this.active = source["active"];
	    }
	}
	export class Snapshot {
	    adapter: string;
	    gateway: string;
	    ip: string;
	    systemProxyOn: boolean;
	    systemProxyAddr: string;
	    proxies: ProxyHint[];
	    tunnels: string[];
	    defaultViaTunnel: boolean;
	    tailscale: string;
	
	    static createFrom(source: any = {}) {
	        return new Snapshot(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.adapter = source["adapter"];
	        this.gateway = source["gateway"];
	        this.ip = source["ip"];
	        this.systemProxyOn = source["systemProxyOn"];
	        this.systemProxyAddr = source["systemProxyAddr"];
	        this.proxies = this.convertValues(source["proxies"], ProxyHint);
	        this.tunnels = source["tunnels"];
	        this.defaultViaTunnel = source["defaultViaTunnel"];
	        this.tailscale = source["tailscale"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace geo {
	
	export class Info {
	    ip: string;
	    country: string;
	    countryCode: string;
	    city: string;
	    lat: number;
	    lon: number;
	    viaProxy: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Info(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.country = source["country"];
	        this.countryCode = source["countryCode"];
	        this.city = source["city"];
	        this.lat = source["lat"];
	        this.lon = source["lon"];
	        this.viaProxy = source["viaProxy"];
	    }
	}
	export class LatLon {
	    lat: number;
	    lon: number;
	
	    static createFrom(source: any = {}) {
	        return new LatLon(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.lat = source["lat"];
	        this.lon = source["lon"];
	    }
	}
	export class Node {
	    n: number;
	    ip: string;
	    rttMs: number;
	    status: string;
	    country?: string;
	    asn?: number;
	    org?: string;
	    private: boolean;
	    host?: string;
	    city?: string;
	    at?: LatLon;
	    guessed?: boolean;
	    implausible?: boolean;
	    ambiguous?: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Node(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.n = source["n"];
	        this.ip = source["ip"];
	        this.rttMs = source["rttMs"];
	        this.status = source["status"];
	        this.country = source["country"];
	        this.asn = source["asn"];
	        this.org = source["org"];
	        this.private = source["private"];
	        this.host = source["host"];
	        this.city = source["city"];
	        this.at = this.convertValues(source["at"], LatLon);
	        this.guessed = source["guessed"];
	        this.implausible = source["implausible"];
	        this.ambiguous = source["ambiguous"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Route {
	    host: string;
	    targetIP: string;
	    nodes: Node[];
	    reached: boolean;
	    break?: Node;
	    home?: string;
	    farCountry: boolean;
	    serviceOK: boolean;
	    opaque: boolean;
	    note?: string;
	    noteId?: string;
	    noteArgs?: string[];
	    anchor?: LatLon;
	
	    static createFrom(source: any = {}) {
	        return new Route(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.host = source["host"];
	        this.targetIP = source["targetIP"];
	        this.nodes = this.convertValues(source["nodes"], Node);
	        this.reached = source["reached"];
	        this.break = this.convertValues(source["break"], Node);
	        this.home = source["home"];
	        this.farCountry = source["farCountry"];
	        this.serviceOK = source["serviceOK"];
	        this.opaque = source["opaque"];
	        this.note = source["note"];
	        this.noteId = source["noteId"];
	        this.noteArgs = source["noteArgs"];
	        this.anchor = this.convertValues(source["anchor"], LatLon);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace history {
	
	export class Entry {
	    // Go type: time
	    at: any;
	    status: string;
	    summary: string;
	    duration: number;
	
	    static createFrom(source: any = {}) {
	        return new Entry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.at = this.convertValues(source["at"], null);
	        this.status = source["status"];
	        this.summary = source["summary"];
	        this.duration = source["duration"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace probe {
	
	export class CertInfo {
	    subject?: string;
	    issuer?: string;
	    nameMatch: boolean;
	    chainValid: boolean;
	    chainErr?: string;
	
	    static createFrom(source: any = {}) {
	        return new CertInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.subject = source["subject"];
	        this.issuer = source["issuer"];
	        this.nameMatch = source["nameMatch"];
	        this.chainValid = source["chainValid"];
	        this.chainErr = source["chainErr"];
	    }
	}
	export class Result {
	    target: string;
	    method: string;
	    path: string;
	    latency: number;
	    status: string;
	    outcome?: string;
	    detail?: string;
	    ips?: string[];
	    code?: number;
	    location?: string;
	    server?: string;
	    cfMitigated?: string;
	    body?: string;
	    challenge?: boolean;
	    sni?: string;
	    cert?: CertInfo;
	
	    static createFrom(source: any = {}) {
	        return new Result(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.target = source["target"];
	        this.method = source["method"];
	        this.path = source["path"];
	        this.latency = source["latency"];
	        this.status = source["status"];
	        this.outcome = source["outcome"];
	        this.detail = source["detail"];
	        this.ips = source["ips"];
	        this.code = source["code"];
	        this.location = source["location"];
	        this.server = source["server"];
	        this.cfMitigated = source["cfMitigated"];
	        this.body = source["body"];
	        this.challenge = source["challenge"];
	        this.sni = source["sni"];
	        this.cert = this.convertValues(source["cert"], CertInfo);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace runner {
	
	export class Report {
	    // Go type: time
	    startedAt: any;
	    duration: number;
	    env: env.Snapshot;
	    results: probe.Result[];
	    layers: verdict.LayerStatus[];
	    services: verdict.ServiceVerdict[];
	    verdict: verdict.Verdict;
	    aborted?: boolean;
	    canceled?: boolean;
	    captive?: string;
	    routes?: geo.Route[];
	    geoDirect?: geo.Info;
	    geoProxy?: geo.Info;
	    geoDataDate?: string;
	
	    static createFrom(source: any = {}) {
	        return new Report(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.startedAt = this.convertValues(source["startedAt"], null);
	        this.duration = source["duration"];
	        this.env = this.convertValues(source["env"], env.Snapshot);
	        this.results = this.convertValues(source["results"], probe.Result);
	        this.layers = this.convertValues(source["layers"], verdict.LayerStatus);
	        this.services = this.convertValues(source["services"], verdict.ServiceVerdict);
	        this.verdict = this.convertValues(source["verdict"], verdict.Verdict);
	        this.aborted = source["aborted"];
	        this.canceled = source["canceled"];
	        this.captive = source["captive"];
	        this.routes = this.convertValues(source["routes"], geo.Route);
	        this.geoDirect = this.convertValues(source["geoDirect"], geo.Info);
	        this.geoProxy = this.convertValues(source["geoProxy"], geo.Info);
	        this.geoDataDate = source["geoDataDate"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace verdict {
	
	export class LayerStatus {
	    layer: string;
	    status: string;
	
	    static createFrom(source: any = {}) {
	        return new LayerStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.layer = source["layer"];
	        this.status = source["status"];
	    }
	}
	export class ServiceVerdict {
	    host: string;
	    directOk: boolean;
	    proxyOk: boolean;
	    proxyTried?: boolean;
	    challenged?: boolean;
	    cause: string;
	
	    static createFrom(source: any = {}) {
	        return new ServiceVerdict(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.host = source["host"];
	        this.directOk = source["directOk"];
	        this.proxyOk = source["proxyOk"];
	        this.proxyTried = source["proxyTried"];
	        this.challenged = source["challenged"];
	        this.cause = source["cause"];
	    }
	}
	export class Verdict {
	    lines: string[];
	    warnings: string[];
	    chain: LayerStatus[];
	
	    static createFrom(source: any = {}) {
	        return new Verdict(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.lines = source["lines"];
	        this.warnings = source["warnings"];
	        this.chain = this.convertValues(source["chain"], LayerStatus);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

