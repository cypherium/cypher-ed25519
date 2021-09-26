// Copyright 2015 The go-ethereum Authors
// Copyright 2017 The cypherBFT Authors
// This file is part of the cypherBFT library.
//
// The cypherBFT library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The cypherBFT library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the cypherBFT library. If not, see <http://www.gnu.org/licenses/>.

// Contains the metrics collected by the downloader.

package downloader

import (
	"github.com/cypherium/cypherBFT/metrics"
)

var (
	headerInMeter      = metrics.NewRegisteredMeter("cph/downloader/headers/in", nil)
	headerReqTimer     = metrics.NewRegisteredTimer("cph/downloader/headers/req", nil)
	headerDropMeter    = metrics.NewRegisteredMeter("cph/downloader/headers/drop", nil)
	headerTimeoutMeter = metrics.NewRegisteredMeter("cph/downloader/headers/timeout", nil)

	bodyInMeter      = metrics.NewRegisteredMeter("cph/downloader/bodies/in", nil)
	bodyReqTimer     = metrics.NewRegisteredTimer("cph/downloader/bodies/req", nil)
	bodyDropMeter    = metrics.NewRegisteredMeter("cph/downloader/bodies/drop", nil)
	bodyTimeoutMeter = metrics.NewRegisteredMeter("cph/downloader/bodies/timeout", nil)

	receiptInMeter      = metrics.NewRegisteredMeter("cph/downloader/receipts/in", nil)
	receiptReqTimer     = metrics.NewRegisteredTimer("cph/downloader/receipts/req", nil)
	receiptDropMeter    = metrics.NewRegisteredMeter("cph/downloader/receipts/drop", nil)
	receiptTimeoutMeter = metrics.NewRegisteredMeter("cph/downloader/receipts/timeout", nil)

	keyBlockInMeter      = metrics.NewRegisteredMeter("cph/downloader/keyBlocks/in", nil)
	keyBlockDropMeter    = metrics.NewRegisteredMeter("cph/downloader/keyBlocks/drop", nil)
	keyBlockReqTimer     = metrics.NewRegisteredTimer("cph/downloader/keyBlocks/req", nil)
	keyBlockTimeoutMeter = metrics.NewRegisteredMeter("cph/downloader/keyBlocks/timeout", nil)

	stateInMeter   = metrics.NewRegisteredMeter("cph/downloader/states/in", nil)
	stateDropMeter = metrics.NewRegisteredMeter("cph/downloader/states/drop", nil)
)
