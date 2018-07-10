package services

import (
	// Importing the services so they register their services to SDA
	// automatically when importing bls-ftcosi/cothority/services
	_ "github.com/dedis/cosi/service"
	_ "bls-ftcosi/cothority/services/byzcoin_ng"
	_ "bls-ftcosi/cothority/services/guard"
	_ "bls-ftcosi/cothority/services/identity"
	_ "bls-ftcosi/cothority/services/skipchain"
	_ "bls-ftcosi/cothority/services/status"
)
