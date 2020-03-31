package proj2

// CS 161 Project 2 Spring 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging, etc...
	"encoding/hex"

	// UUIDs are generated right based on the cryptographic PRNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"

	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes: 
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
        var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

func getHKDFKey(password []byte, username []byte) (hkdfKey []byte) {
	//MAC key generated for MAC'ing
	hkdfKey = userlib.Argon2Key(password, username, 32)
	return hkdfKey
}

func encryptionHelper(password []byte, username []byte) (macKey []byte, symmKey []byte) {
	//MAC key generated for MAC'ing
	var hkdfKey = userlib.Argon2Key(password, username, 32)
	macKey, _ = userlib.HashKDF(hkdfKey, []byte("mac"))
	macKey = macKey[:16]
	//Symmetric key generated used for symmetric encryption
	symmKey, _ = userlib.HashKDF(hkdfKey, []byte("symmetric key"))
	symmKey = symmKey[:16]
	return macKey, symmKey
}

// The structure definition for a user record
type User struct {
	Username string
	Password string
	SecretKeyEnc userlib.PKEDecKey
	DSSignKey userlib.DSSignKey
	AccessTokenMap map[string] AccessToken
	//TODO: Add files and access tokens


	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

//Access Token object with the symmetric key and the unique identifier which shouldn't reveal
//anything about the filename
type AccessToken struct {
	 SymmetricKey[] byte
	 UniqueIdentifier[] byte
	 MacKey[] byte
}

type File struct {
	Contents[][] byte
	//SharingTree SharingTree
}

//Generates a unique access token object for a filename
func (user *User) GenerateAccessToken(filename string) (accessToken AccessToken){
	hkdfKey := getHKDFKey([]byte(user.Username), []byte(user.Password))
	symmKey, _ := userlib.HashKDF(hkdfKey, []byte(filename)) //TODO: this could be repeating for the same filename!
	uI := userlib.RandomBytes(16)
	macKey := userlib.RandomBytes(16)
	accessToken.MacKey = macKey
	accessToken.SymmetricKey = symmKey
	accessToken.UniqueIdentifier = uI
	return accessToken
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the password has strong entropy, EXCEPT
// the attackers may possess a precomputed tables containing 
// hashes of common passwords downloaded from the internet.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	//TODO: This is a toy implementation.
	macKey, symmetricKey := encryptionHelper([]byte(password), []byte(username))

	//Generate public & private keys for public key crypto. RSA Encryption guarantees confidentiality for asymmetric-keys.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()

	//Generate public & private keys for digital signatures. RSA Signatures guarantee integrity + authenticity for asymmetric-keys.
	var vk userlib.DSVerifyKey
	var dssk userlib.DSSignKey
	dssk, vk, _ = userlib.DSKeyGen()

	errorPKE := userlib.KeystoreSet(username + " " + "public key", pk) //storing public key in Keystore
	errorDS := userlib.KeystoreSet(username + " " + "verify key", vk) //storing verify key in Keystore

	//error if username already exists
	if errorPKE != nil {
		return nil, errorPKE
	} else if errorDS != nil {
		return nil, errorDS
	}

	var macUsername, _ = userlib.HMACEval(macKey, []byte(username)) //Hash (MAC) username so that we can use bytesToUUID

	//Storing username, secret key, and signing key in user struct
	userdata.Username = username
	userdata.Password = password
	userdata.DSSignKey = dssk
	userdata.SecretKeyEnc = sk

	// TODO: Make empty File map? For now, assuming we add file map in StoreFile.
	/*userdata.FileMap = make(map[string][]byte)
	userdata.FileNames = ""
	userdata.FileContents = nil*/

	userdata.AccessTokenMap = make(map[string] AccessToken)




	var UUID = bytesToUUID(macUsername)
	//Marshal the userdata struct, so it's JSON encoded.
	var data, _ = json.Marshal(userdata)
	//encrypt user data
	var encryptedData = userlib.SymEnc(symmetricKey, userlib.RandomBytes(16), data)
	//mac user data
	var MAC, _ = userlib.HMACEval(macKey, encryptedData)

	var dataPlusMAC =  append(encryptedData[:], MAC[:]...) //appending MAC to encrypted user struct
	//print(len(x) == len(encryptedData) + len(MAC))
	//println("TOTAL:")
	//println(x)

	userlib.DatastoreSet(UUID, dataPlusMAC)
	//********************************** END OF NEW IMPLEMENTATION *****************************************************************
	return &userdata, nil
}



// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	macKey, symmKey := encryptionHelper([]byte(password), []byte(username))
	var macUsername, _ = userlib.HMACEval(macKey, []byte(username)) //Hash (MAC) username so that we can use bytesToUUID
	var UUID = bytesToUUID(macUsername)
	var data, ok = userlib.DatastoreGet(UUID)
	if ok == false {
		return nil, errors.New("Username/Password invalid")
	}
	//println(" ")
	//println("AT GET USER")
	//println("LENGTH OF DATA: ", data)
	var ciphertext = data[0: len(data) - 64]
	var macRec = data[len(data) - 64: ] //Mac received from Datastore
	var macComp, _ = userlib.HMACEval(macKey, ciphertext) //recompute MAC

	if userlib.HMACEqual(macRec, macComp) == false {
		return nil, errors.New("data corrupted")
	}

	//Data is now verified, can decrypt data
	var decryptedData = userlib.SymDec(symmKey, ciphertext)
	_ = json.Unmarshal(decryptedData, userdataptr)
	//println("Printing user struct fields after calling storefile: ")
	//println("username: ", userdataptr.Username)
	//println("password: ", userdataptr.Password)
	//println("MAC: ", userdataptr.MAC)
	//println("File name: ", userdataptr.FileNames)
	//println("File contents: ", userdataptr.FileContents)

	//println("File Map: ", userdataptr.FileMap)
	//zeroKey := make([]byte, 16) //byte array of 16 0's
	//macFilename, _ := userlib.HMACEval(zeroKey, []byte("file1")) // HashFunction(filename) = HMAC(0, filename)
	//println("filename: ", string(macFilename))
	//v, ok := userdataptr.FileMap[string(macFilename)]
	//v = v
	//println("KEY SHOULD BE THERE! 89(EQUALS TRUE!) : ", ok)
	//println("filename value: ", v)
	//println("END OF GET USER")
	//println("")
	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename 
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	//TODO: This is a toy implementation.
	//encrypt and MAC the file
	username := userdata.Username
	password := userdata.Password
	macKey, symmKey := encryptionHelper([]byte(password), []byte(username))


	//fileMap := make(map[string][]byte)

	//******************************START NEW IMPLEMENTATION ***************************************
	var fileMapData map[string] File

	//TODO: Verify integrity of map
	//TODO: decrypt map



	accessToken := userdata.GenerateAccessToken(filename) //generate access token

	//Encrypt File Contents
	encrypedContents := userlib.SymEnc(accessToken.SymmetricKey, userlib.RandomBytes(16), data)
	encMacContents, _ := userlib.HMACEval(accessToken.MacKey, encrypedContents)



	//Mac File Contents

	//Create File

	//Store in DataStore




	userdata.AccessTokenMap[filename] = accessToken //store access token associated with filename

	fileMapData[string(accessToken.UniqueIdentifier)] = data








	macUsername, _ := userlib.HMACEval(macKey, []byte(filename))

	var UUID = bytesToUUID(macUsername)
	//Marshal the userdata struct, so it's JSON encoded.
	var newUserData, _ = json.Marshal(userdata)
	//encrypt user data
	var encryptedData = userlib.SymEnc(symmKey, userlib.RandomBytes(16), newUserData)
	//mac user data
	var MAC, _ = userlib.HMACEval(macKey, encryptedData)
	var dataPlusMAC = append(encryptedData[:], MAC[:]...) //appending MAC to encrypted user struct
	println("Encrypted user struct with newly added file: ", dataPlusMAC)
	userlib.DatastoreSet(UUID, dataPlusMAC)
	//******************************END NEW IMPLEMENTATION ***************************************


/*

	// Use hash function to hide the filename length.
	//zeroKey := make([]byte, 16) //byte array of 16 0's
	macFilename, _ := userlib.HMACEval(macKey, []byte(filename)) // HashFunction(filename) = HMAC(0, filename)
	//println("MAC Filename: ", string(macFilename))
	//TODO: If the file has been shared with others, the file must stay shared.
	//Marshal the file contents, so it's JSON encoded.
	//println("Data in string form: ", string(data))
	//var marshalFileData, _ = json.Marshal(data)
	//encrypt file contents
	var encryptedFileData = userlib.SymEnc(symmKey, userlib.RandomBytes(16), data)
	//mac file contents
	var fileDataMAC, _ = userlib.HMACEval(macKey, encryptedFileData)
	var encMACFile =  append(encryptedFileData[:], fileDataMAC[:]...) //appending MAC to encrypted file contents
	userdata.FileMap[string(macFilename)] = encMACFile

	//update FileMap
	//for k,v := range fileMap {
	//	userdata.FileMap[k] = v
	//}

	//get user data from DataStore.
	//_, err := GetUser(username, password)
	//if err != nil {
	//	print("Error occurred when trying to get user data from DataStore. ")
	//	return
	//}
	//println("FILE CONTENTS EXIST UP UNTIL HERE!")
	userdata.FileNames = string(macFilename)
	userdata.FileContents = encMACFile


	var macUsername, _ = userlib.HMACEval(macKey, []byte(username)) //Hash (MAC) username so that we can use bytesToUUID
	var UUID = bytesToUUID(macUsername)
	//Marshal the userdata struct, so it's JSON encoded.
	var newUserData, _ = json.Marshal(userdata)
	//encrypt user data
	var encryptedData = userlib.SymEnc(symmKey, userlib.RandomBytes(16), newUserData)
	//mac user data
	var MAC, _ = userlib.HMACEval(macKey, encryptedData)
	var dataPlusMAC = append(encryptedData[:], MAC[:]...) //appending MAC to encrypted user struct
	//println("Encrypted user struct with newly added file: ", dataPlusMAC)
	userlib.DatastoreSet(UUID, dataPlusMAC)
	//End of toy implementation

*/
	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	username := userdata.Username
	password := userdata.Password
	currentUserData, err := GetUser(username, password)
	fileMap := currentUserData.FileMap

	zeroKey := make([]byte, 16) //byte array of 16 0's
	macFilename, _ := userlib.HMACEval(zeroKey, []byte(filename)) // HashFunction(filename) = HMAC(0, filename)
	existingFileContents, present := fileMap[string(macFilename)]
	// If the file does not exist, return an error.
	if present == false {
		return errors.New("file does not exist")
	} else {	//Appends to the file, if it exists.
		//get existing file data and MAC
		existingFileData := existingFileContents[:len(existingFileContents)-64]
		existingFileMAC := existingFileContents[len(existingFileContents)-64:]
		//encrypt data you want to append to existing file contents.
		macKey, symmKey := encryptionHelper([]byte(password), []byte(username))
		var marshalFileData, _ = json.Marshal(data)
		// new file data and MAC we want to append
		var newFileData = userlib.SymEnc(symmKey, userlib.RandomBytes(16), marshalFileData)
		var newFileMAC, _ = userlib.HMACEval(macKey, newFileData)
		// appending new and old file data and MACs.
		combinedFile := append(existingFileData[:], newFileData[:]...)
		combinedMAC := append(existingFileMAC[:], newFileMAC[:]...)
		zeroKey := make([]byte, 16) //byte array of 16 0's
		combinedMAC, _ = userlib.HMACEval(zeroKey, combinedMAC)
		combinedFileContents :=  append(combinedFile[:], combinedMAC[:]...)
		fileMap[filename] = combinedFileContents
		currentUserData.FileMap = fileMap
		//get UUID
		var macUsername, _ = userlib.HMACEval(macKey, []byte(username)) //Hash (MAC) username so that we can use bytesToUUID
		var UUID = bytesToUUID(macUsername)
		// re-encrypt user struct again.
		// HELP! This is hella inefficient though, but it seems like the append efficiency requirement just refers to append.
		var marshalUserData, _ = json.Marshal(currentUserData)
		var encryptedData = userlib.SymEnc(symmKey, userlib.RandomBytes(16), marshalUserData)
		var MAC, _ = userlib.HMACEval(macKey, encryptedData)
		var dataPlusMAC =  append(encryptedData[:], MAC[:]...) //appending MAC to encrypted user struct
		userlib.DatastoreSet(UUID, dataPlusMAC)
		return nil
	}
	//You are not required to check the integrity of the existing file (integrity verification is allowed but not required).
	// If you detect an integrity violation or the append operation cannot proceed for any reason, trigger an error.
	return errors.New("Integrity violation or couldn't append. ")
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	username := userdata.Username
	password := userdata.Password
	macKey, _ := encryptionHelper([]byte(password), []byte(username))

	macFileName, _ := userlib.HMACEval(macKey, []byte(filename))
	encMacfile, ok := userdata.FileMap[string(macFileName)]
	if ok {
		//if file is locally saved, load
		return encMacfile, nil
	} else {

	}

/*
	currentUserData, err := GetUser(username, password)

	//If user struct is corrupted, error
	if err != nil {
		return nil, err
	}



	//fileMap := currentUserData.FileMap

	macFilename, _ := userlib.HMACEval(zeroKey, []byte(filename)) // HashFunction(filename) = HMAC(0, filename)
	println("MAC Filename: ", string(macFilename))
	//println("fileMap[string(macFilename)]: ", fileMap[string(macFilename)])
	existingFileContents := currentUserData.FileContents

	var decryptedData = userlib.SymDec(symmKey, existingFileContents)
	println("Decrypted File Contents: ", decryptedData)
	//if present == false {
	//	return nil, errors.New(strings.ToTitle("File not found!"))
	//}
	if currentUserData.FileNames == "" {
		return nil, errors.New(strings.ToTitle("File not found!"))
	} else {	//Loads the latest version of a file, if it exists.
		//get existing file data and MAC in plaintext form.
		existingFileData := existingFileContents[:len(existingFileContents)-64]
		existingFileMAC := existingFileContents[len(existingFileContents)-64:]
		//get mac and symm keys.
		macKey, symmKey := encryptionHelper([]byte(password), []byte(username))
		var recomputedFileMAC, _ = userlib.HMACEval(macKey, existingFileData) //recompute MAC

		if userlib.HMACEqual(existingFileMAC, recomputedFileMAC) == false {
			return nil, errors.New("data corrupted")
		}
		//Data is now verified, can decrypt data
		var decryptedData = userlib.SymDec(symmKey, existingFileData)
		print("DECRYPTED DATA: ", decryptedData)
		json.Unmarshal(decryptedData, &data)
		return data, nil

	}



	//var macUsername, _ = userlib.HMACEval(macKey, []byte(username)) //Hash (MAC) username so that we can use bytesToUUID
	//var UUID = bytesToUUID(macUsername)
	//packaged_data, ok := userlib.DatastoreGet(UUID)
	//var newFileData = userlib.SymDec(symmKey, packaged_data)


	//TODO: This is a toy implementation.
	//UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	//packaged_data, ok := userlib.DatastoreGet(UUID)
	//if !ok {
	//	return nil, errors.New(strings.ToTitle("File not found!"))
	//}
	//json.Unmarshal(packaged_data, &data)
	//return data, nil
	//End of toy implementation


 */
	return encMacfile, nil
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {

	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	return
}
