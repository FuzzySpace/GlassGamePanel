package fixture

// NonDenyServerID is a commercial-shaped fixture (SID 19). It is not on the
// managed-inventory deny map. TEST inventory_only may plan it and must not dispatch.
const NonDenyServerID = "11111111-1111-4111-8111-111111111111"

// CommercialGlassID is the planned Glass UUID for the non-deny fixture.
// It is assigned in memory only; Wings is not provisioned.
const CommercialGlassID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

// BackupID is a fixture backup id for restore stubs.
const BackupID = "22222222-2222-4222-8222-222222222222"

// SourceServer is one row of the in-process Ptero inventory fixture.
// These rows are used only when PTERO_SOURCE_API_URL is unset. The fixture
// path does not dial a source panel.
type SourceServer struct {
	SourceServerID   string
	SourceName       string
	SID              int
	ExternalID       string
	WHMCSServiceID   string
	ManagedInventory bool
}

// WHMCSDenyFixtures are synthetic source rows that carry CT210/211/1220.
// Their UUIDs are not Wings managed-inventory UUIDs; they are denied by WHMCS CT.
func WHMCSDenyFixtures() []SourceServer {
	return []SourceServer{
		{SourceServerID: "c210c210-0210-4210-8210-210210210210", SourceName: "WHMCS CT210 fixture", WHMCSServiceID: "210", ManagedInventory: true},
		{SourceServerID: "c211c211-0211-4211-8211-211211211211", SourceName: "WHMCS CT211 fixture", WHMCSServiceID: "211", ManagedInventory: true},
		{SourceServerID: "12201220-1220-4220-8220-122012201220", SourceName: "WHMCS CT1220 fixture", WHMCSServiceID: "1220", ManagedInventory: true},
	}
}

// CommercialFixture is the only importable inventory row on TEST.
func CommercialFixture() SourceServer {
	return SourceServer{
		SourceServerID:   NonDenyServerID,
		SourceName:       "Commercial Fixture",
		SID:              19,
		ExternalID:       "19",
		ManagedInventory: false,
	}
}
