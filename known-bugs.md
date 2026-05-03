# Known Bugs

- Multiple local elections are not disambiguated; the frontend uses the first servable `AnonymousElection` returned by storage order.
- Voters with already conflicted ballots may be able to submit another conflicted ballot attempt and see a confusing success path.
