package deny

// catalog pairs managed-inventory deny membership with descriptive refs.
// Membership is authoritative only when it equals managed-inventory-deny.json.
// Ports are descriptive and are not deny keys. Do not republish this list in
// human-facing OpenAPI or docs prose.
var catalog = []serverRef{
	{SID: 43, UUID: "d0ea9cbd-9706-443b-a734-d98a5055a450", ExternalID: "47", Name: "GlassMC Hytale", Port: 5500},
	{SID: 46, UUID: "f060b25f-d720-4f36-ad00-2edba918eef0", ExternalID: "48", Name: "Glass-MC Velocity", Port: 25566},
	{SID: 47, UUID: "fdbfea6b-83aa-4fa3-8456-86f84369916c", ExternalID: "30", Name: "GlassMC-Lobby", Port: 25642},
	{SID: 48, UUID: "54f48d15-89e8-44e3-949c-f980547aedaf", ExternalID: "43", Name: "Glass-MC Palworld", Port: 5502},
	{SID: 49, UUID: "cfe08e83-08f9-4515-a5d3-f84737b6723a", ExternalID: "53", Name: "GlassMC HyTale", Port: 5501},
	{SID: 99, UUID: "eaf90a23-50c5-43c5-bd57-9bd25bf6b22a", ExternalID: "70", Name: "Glass-MC_SMP", Port: 25665},
	{SID: 100, UUID: "8fc56418-30ac-4273-9e9a-1cdf9a24d7fd", ExternalID: "71", Name: "Glass-MC_Parkour", Port: 25666},
	{SID: 101, UUID: "10f50377-a420-4269-8a09-a8fac9da27b8", ExternalID: "72", Name: "Glass-MC_Dungeons", Port: 25667},
}

// whmcsCTs is the managed-inventory WHMCS service deny set.
var whmcsCTs = []int{210, 211, 1220}
