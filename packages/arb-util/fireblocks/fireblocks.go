/*
 * Copyright 2021, Offchain Labs, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fireblocks

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/rs/zerolog/log"

	"github.com/offchainlabs/arbitrum/packages/arb-util/fireblocks/accounttype"
	"github.com/offchainlabs/arbitrum/packages/arb-util/fireblocks/operationtype"
)

var logger = log.With().Caller().Stack().Str("component", "fireblocks").Logger()

type Fireblocks struct {
	apiKey     string
	assetId    string
	baseUrl    string
	signKey    *rsa.PrivateKey
	sourceId   string
	sourceType accounttype.AccountType
}

type CreateNewTransactionBody struct {
	AssetId         string                          `json:"assetId"`
	Source          TransferPeerPath                `json:"source"`
	Destination     DestinationTransferPeerPath     `json:"destination"`
	Amount          string                          `json:"amount"`
	Fee             string                          `json:"fee,omitempty"`
	GasPrice        string                          `json:"gasPrice,omitempty"`
	GasLimit        string                          `json:"gasLimit,omitempty"`
	NetworkFee      string                          `json:"networkFee,omitempty"`
	FeeLevel        string                          `json:"feeLevel,omitempty"`
	MaxFee          string                          `json:"maxFee,omitempty"`
	FailOnLowFee    bool                            `json:"failOnLowFee,omitempty"`
	Note            string                          `json:"note,omitempty"`
	Operation       operationtype.OperationType     `json:"operation,omitempty"`
	CustomerRefId   string                          `json:"customerRefId,omitempty"`
	Destinations    []TransactionRequestDestination `json:"destinations,omitempty"`
	ExtraParameters TransactionExtraParameters      `json:"extraParameters"`
}

type TransactionExtraParameters struct {
	ContractCallData string `json:"contractCallData"`
}

type TransferPeerPath struct {
	Type accounttype.AccountType `json:"type"`
	Id   string                  `json:"id"`
}

type DestinationTransferPeerPath struct {
	Type           accounttype.AccountType `json:"type"`
	Id             string                  `json:"id,omitempty"`
	OneTimeAddress OneTimeAddress          `json:"oneTimeAddress,omitempty"`
}

type OneTimeAddress struct {
	Address string `json:"address"`
	Tag     string `json:"tag"`
}

type CreateTransactionResponse struct {
	Id     string `json:"id"`
	Status string `json:"status"`
}

type TransactionDetails struct {
	Id                            string                   `json:"id"`
	AssetId                       string                   `json:"assetId"`
	Source                        TransferPeerPathResponse `json:"source"`
	Destination                   TransferPeerPathResponse `json:"destination"`
	RequestedAmount               int64                    `json:"requestedAmount"`
	AmountInfo                    AmountInfo               `json:"amountInfo"`
	FeeInfo                       FeeInfo                  `json:"feeInfo"`
	Amount                        int64                    `json:"amount"`
	NetAmount                     float32                  `json:"NetAmount"`
	AmountUSD                     float32                  `json:"amountUSD"`
	ServiceFee                    float32                  `json:"serviceFee"`
	NetworkFee                    float32                  `json:"networkFee"`
	CreatedAt                     int64                    `json:"createdAt"`
	LastUpdate                    int64                    `json:"lastUpdate"`
	Status                        string                   `json:"transactionStatus"`
	TxHash                        string                   `json:"txHash"`
	SubStatus                     string                   `json:"transactionSubStatus"`
	DestinationAddress            string                   `json:"destinationAddress"`
	DestinationAddressDescription string                   `json:"destinationAddressDescription"`
	DestinationTag                string                   `json:"destinationTag"`
	SignedBy                      []string                 `json:"signedBy"`
	CreatedBy                     string                   `json:"createdBy"`
	RejectedBy                    string                   `json:"rejectedBy"`
	AddressType                   string                   `json:"addressType"`
	Note                          string                   `json:"note"`
	ExchangeTxId                  string                   `json:"exchangeTxId"`
	FeeCurrency                   string                   `json:"feeCurrency"`
	Operation                     string                   `json:"operation"`
	AmlScreeningResult            AmlScreeningResult       `json:"amlScreeningResult"`
	CustomerRefId                 string                   `json:"customerRefId"`
	NumOfConfirmations            int                      `json:"numOfConfirmations"`
	NetworkRecords                []string                 `json:"networkRecords"`
	ReplacedTxHash                string                   `json:"replacedTxHash"`
	Destinations                  []DestinationsResponse   `json:"destinations"`
	SignedMessages                []SignedMessage          `json:"signedMessages"`
	ExtraParameters               string                   `json:"extraParameters"`
}

type TransferPeerPathResponse struct {
	Type    string `json:"type"`
	Id      string `json:"id"`
	Name    string `json:"name"`
	SubType string `json:"subType"`
}

type AmountInfo struct {
	Amount          string `json:"amount"`
	RequestedAmount string `json:"requestedAmount"`
	NetAmount       string `json:"netAmount"`
	AmountUSD       string `json:"amountUSD"`
}

type FeeInfo struct {
	NetworkFee string `json:"networkFee"`
	ServiceFee string `json:"serviceFee"`
}

type NetworkRecord struct {
	Source             TransferPeerPathResponse `json:"source"`
	Destination        TransferPeerPathResponse `json:"destination"`
	TxHash             string                   `json:"txHash"`
	NetworkFee         int64                    `json:"networkFee"`
	AssetId            string                   `json:"assetId"`
	NetAmount          int64                    `json:"netAmount"`
	Status             string                   `json:"status"`
	Type               string                   `json:"type"`
	DestinationAddress string                   `json:"destinationAddress"`
}

type AmlScreeningResult struct {
	Operation string `json:"amlScreeningResult"`
}

type SignedMessage struct {
	Content        string     `json:"content"`
	Algorithm      string     `json:"algorithm"`
	DerivationPath []int      `json:"derivationPath"`
	Signature      Dictionary `json:"signature"`
	PublicKey      string     `json:"publicKey"`
}

type Dictionary map[string]interface{}

type DestinationsResponse struct {
	Amount                        string             `json:"amount"`
	Destination                   string             `json:"destination"`
	AmountUSD                     string             `json:"amountUSD"`
	DestinationAddress            string             `json:"destinationAddress"`
	DestinationAddressDescription string             `json:"destinationAddressDescription"`
	AmlScreeningResult            AmlScreeningResult `json:"amlScreeningResult"`
	CustomerRefId                 string             `json:"customerRefId"`
}

type VaultAccount struct {
	Id            string       `json:"id"`
	Name          string       `json:"name"`
	HiddenOnUI    bool         `json:"hiddenOnUI"`
	CustomerRefId string       `json:"customerRefId,omitempty"`
	AutoFuel      bool         `json:"autoFuel"`
	Assets        []VaultAsset `json:"assets"`
}

type VaultAsset struct {
	Id                   string `json:"id"`
	Total                string `json:"total"`
	Balance              string `json:"balance"`
	Available            string `json:"available"`
	Pending              string `json:"pending"`
	LockedAmount         string `json:"lockedAmount"`
	TotalStakedCPU       string `json:"totalStakedCPU"`
	SelfStakedCPU        string `json:"selfStakedCPU"`
	SelfStakedNetwork    string `json:"selfStakedNetwork"`
	PendingRefundCPU     string `json:"pendingRefundCPU"`
	PendingRefundNetwork string `json:"pendingRefundNetwork"`
}

type TransactionRequestDestination struct {
	Amount      string `json:"amount"`
	Destination string `json:"destination"`
}

type fireblocksClaims struct {
	Uri      string `json:"uri"`
	Nonce    int64  `json:"nonce"`
	Iat      int64  `json:"iat"`
	Exp      int64  `json:"exp"`
	Sub      string `json:"sub"`
	BodyHash string `json:"bodyHash"`
	jwt.StandardClaims
}

func New(assetId string, baseUrl string, sourceType accounttype.AccountType, sourceId string, apiKey string, signKey *rsa.PrivateKey) *Fireblocks {
	rand.Seed(time.Now().UnixNano())
	return &Fireblocks{
		apiKey:     apiKey,
		assetId:    assetId,
		baseUrl:    baseUrl,
		signKey:    signKey,
		sourceId:   sourceId,
		sourceType: sourceType,
	}
}

func (fb *Fireblocks) ListTransactions() (*[]TransactionDetails, error) {
	resp, err := fb.sendRequest("/v1/transactions", nil)
	if err != nil {
		return nil, err
	}

	var result []TransactionDetails
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, err
	}

	return &result, err
}

func (fb *Fireblocks) ListVaultAccounts() (*[]VaultAccount, error) {
	resp, err := fb.sendRequest("/v1/vault/accounts", nil)
	if err != nil {
		return nil, err
	}

	var result []VaultAccount
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, err
	}

	return &result, err
}

func (fb *Fireblocks) CreateNewContractCall(destinationType accounttype.AccountType, destinationId string, destinationTag string, callData string) (*[]CreateTransactionResponse, error) {
	return fb.CreateNewTransaction(destinationType, destinationId, destinationTag, "0", operationtype.ContractCall, callData)
}

func (fb *Fireblocks) CreateNewTransaction(destinationType accounttype.AccountType, destinationId string, destinationTag string, amount string, operation operationtype.OperationType, callData string) (*[]CreateTransactionResponse, error) {

	destination := DestinationTransferPeerPath{Type: destinationType}
	if destination.Type == accounttype.OneTimeAddress {
		destination.OneTimeAddress = OneTimeAddress{
			Address: destinationId,
		}
		if len(destinationTag) > 0 {
			destination.OneTimeAddress.Tag = destinationTag
		}
	} else {
		destination.Id = destinationId
	}

	body := &CreateNewTransactionBody{
		AssetId:         fb.assetId,
		Source:          TransferPeerPath{Type: fb.sourceType, Id: fb.sourceId},
		Destination:     destination,
		Amount:          amount,
		Operation:       operation,
		ExtraParameters: TransactionExtraParameters{ContractCallData: callData},
	}

	jsonData, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	logger.Debug().RawJSON("request", jsonData).Msg("creating new fireblocks transaction")
	resp, err := fb.sendRequest("/v1/transactions", jsonData)
	if err != nil {
		return nil, err
	}

	var result []CreateTransactionResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, err
	}

	if len(result) > 0 {
		logger.Debug().Str("id", result[0].Id).Str("status", result[0].Status).Msg("fireblocks response")
	}
	return &result, err
}

func (fb *Fireblocks) sendRequest(path string, body []byte) (*http.Response, error) {
	token, err := fb.signJWT(path, body)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	url := fb.baseUrl + path
	req, err := http.NewRequest("GET", url, bytes.NewBuffer(body))
	if err != nil {
		logger.
			Error().
			Err(err).
			Str("url", fb.baseUrl).
			Msg("error creating new fireblocks request")
		return nil, err
	}
	req.Header.Add("Accept", "*/*")
	req.Header.Add("X-API-Key", fb.apiKey)
	req.Header.Add("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		logger.
			Error().
			Err(err).
			Str("url", fb.baseUrl).
			Msg("error doing fireblocks request")
		return nil, err
	}

	if resp.StatusCode >= 300 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logger.
				Error().
				Err(err).
				Str("url", url).
				Str("status", resp.Status).
				Msg("error reading body after posting fireblocks request")
			return nil, fmt.Errorf("status '%s' posting fireblocks request", resp.Status)
		}

		bodyStr := string(body)
		logger.
			Error().
			Str("url", url).
			Str("status", resp.Status).
			Str("body", bodyStr).
			Msg("error returned when posting fireblocks request")
		return nil, fmt.Errorf("status '%s' posting fireblocks request", resp.Status)
	}

	return resp, nil
}

func (fb *Fireblocks) signJWT(path string, body []byte) (string, error) {
	newPath := strings.Replace(path, "[", "%5B", -1)
	newPath = strings.Replace(newPath, "]", "%5D", -1)
	now := time.Now().Unix()
	quotedBody := strconv.Quote(string(body))
	bodyHash := sha256.Sum256([]byte(quotedBody))

	claims := fireblocksClaims{
		Uri:      newPath,
		Nonce:    rand.Int63(),
		Iat:      now,
		Exp:      now + 55,
		Sub:      fb.apiKey,
		BodyHash: hex.EncodeToString(bodyHash[:]),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	return token.SignedString(fb.signKey)
}
