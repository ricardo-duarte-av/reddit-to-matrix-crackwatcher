package main

import "testing"

func TestCleanGameName(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// Markdown stripping
		{"**Hogwarts Legacy Complete**", "Hogwarts Legacy"},
		{"[Mittelland AD](https://example.com)", "Mittelland AD"},
		// Edition qualifiers
		{"Charm and Clue 2 Collectors Edition", "Charm and Clue 2"},
		{"Iron Sky Invasion UHD Directors Cut", "Iron Sky Invasion"},
		{"Frostpunk 2 Deluxe Edition", "Frostpunk 2"},
		{"The House of Da Vinci Enhanced", "The House of Da Vinci"},
		{"Sid Meiers Civilization VII Deluxe Edition Hypervisor", "Sid Meiers Civilization VII"},
		{"Two Point Museum Explorer Edition Hypervisor", "Two Point Museum"},
		{"Jurassic World Evolution 3 Deluxe Edition Hypervisor", "Jurassic World Evolution 3"},
		{"Das Rettungsteam Phantomkrise Sammleredition", "Das Rettungsteam Phantomkrise"},
		// Must be left intact (real titles / DLC names)
		{"Workers and Resources Soviet Republic", "Workers and Resources Soviet Republic"},
		{"Sins of a Solar Empire II", "Sins of a Solar Empire II"},
		{"Frostpunk 2 Breach of Trust", "Frostpunk 2 Breach of Trust"},
		{"Besiege The Broken Beyond", "Besiege The Broken Beyond"},
		{"Heroes of Science and Fiction Typhon Map Pack", "Heroes of Science and Fiction Typhon Map Pack"},
		{"2064 Read Only Memories", "2064 Read Only Memories"},
		// Bare "HD" is part of the title (HD remakes have separate IGDB entries)
		{"Final Fantasy X HD", "Final Fantasy X HD"},
		{"The Legend of Zelda Wind Waker HD", "The Legend of Zelda Wind Waker HD"},
	}
	for _, c := range cases {
		if got := cleanGameName(c.in); got != c.want {
			t.Errorf("cleanGameName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
