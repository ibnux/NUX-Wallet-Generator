var _hash = {
	init: SHA256_init,
	update: SHA256_write,
	getBytes: SHA256_finalize,
};

function simpleHash(message) {
	_hash.init();
	_hash.update(message);
	return _hash.getBytes();
}

function getPublicKey(secretPhrase) {
	var secretPhraseBytes = converters.stringToByteArray(secretPhrase);
	var digest = simpleHash(secretPhraseBytes);
	return curve25519.keygen(digest).p;
}

function byteArrayToBigInteger(byteArray, startIndex) {
	var value = new BigInteger("0", 10);
	var temp1, temp2;
	for (var i = byteArray.length - 1; i >= 0; i--) {
		temp1 = value.multiply(new BigInteger("256", 10));
		temp2 = temp1.add(new BigInteger(byteArray[i].toString(10), 10));
		value = temp2;
	}

	return value;
}

function getAccountIdFromPublicKey(publicKey, RSFormat) {
	var hex = converters.hexStringToByteArray(publicKey);

	_hash.init();
	_hash.update(hex);

	var account = _hash.getBytes();

	account = converters.byteArrayToHexString(account);

	var slice = converters.hexStringToByteArray(account).slice(0, 8);

	var accountId = byteArrayToBigInteger(slice).toString();

	if (RSFormat) {
		var address = new NxtAddress();

		if (address.set(accountId)) {
			return address.toString();
		} else {
			return "";
		}
	} else {
		return accountId;
	}
}

function pad(length, val) {
	var array = [];
	for (var i = 0; i < length; i++) {
		array[i] = val;
	}
	return array;
}

function positiveByteArray(byteArray) {
	return converters.hexStringToByteArray(
		converters.byteArrayToHexString(byteArray)
	);
}

function sendMoney(recipient, amount, secretPhrase) {
	//var data = converters.byteArrayToHexString( result_this_ function );
	var txbytes = [];
	txbytes.push(0); // type
	txbytes.push(0 + (1 << 4)); // version/type
	txbytes = txbytes.concat(nxtTimeBytes()); // timestmp
	txbytes = txbytes.concat(wordBytes(1440)); // deadline
	txbytes = txbytes.concat(getPublicKey(secretPhrase)); // public Key
	var recipientRS = recipient;

	var rec = new NxtAddress();
	rec.set(recipientRS);

	var recip = new BigInteger(rec.account_id()).toByteArray().reverse();
	if (recip.length == 9) recip = recip.slice(0, 8);
	while (recip.length < 8) recip = recip.concat(pad(1, 0));
	txbytes = txbytes.concat(recip);

	var amt = new BigInteger(String(parseInt(amount * 100000000)))
		.toByteArray()
		.reverse();
	if (amt.length == 9) amt = amt.slice(0, 8);
	while (amt.length < 8) amt = amt.concat(pad(1, 0));
	txbytes = txbytes.concat(amt);

	var fee = converters.int32ToBytes(100000000);
	while (fee.length < 8) fee = fee.concat(pad(1, 0));
	txbytes = txbytes.concat(fee);

	txbytes = txbytes.concat(pad(32, 0)); // ref full hash
	txbytes = txbytes.concat(pad(64, 0)); // signature

	if (recipient.indexOf("NUX-") == 0) {
		txbytes = txbytes.concat(pad(16, 0)); // ignore everything else
	} else {
		txbytes.push(4);
		txbytes = txbytes.concat(pad(3, 0));
		txbytes = txbytes.concat(pad(12, 0));
		txbytes = txbytes.concat([1]);
		txbytes = txbytes.concat(converters.hexStringToByteArray(recipient));
	}

	txbytes = positiveByteArray(txbytes);
	var sig = signBytes(txbytes, secretPhrase);

	var signable = txbytes.slice(0, 96);
	signable = signable.concat(sig);
	signable = signable.concat(txbytes.slice(96 + 64));

	// now we have a full tx... convert to hex
	return converters.byteArrayToHexString(signable);
}

function signBytes(message, secretPhrase) {
	var messageBytes = message;
	var secretPhraseBytes = converters.stringToByteArray(secretPhrase);

	var digest = simpleHash(secretPhraseBytes);
	var s = curve25519.keygen(digest).s;

	var m = simpleHash(messageBytes);

	_hash.init();
	_hash.update(m);
	_hash.update(s);
	var x = _hash.getBytes();

	var y = curve25519.keygen(x).p;

	_hash.init();
	_hash.update(m);
	_hash.update(y);
	var h = _hash.getBytes();

	var v = curve25519.sign(h, x, s);

	return v.concat(h);
}

function nxtTimeBytes() {
	return converters.int32ToBytes(currentNxtTime());
}

function currentNxtTime() {
	return (Math.floor(Date.now()) - $("#signed_transaction").val()) / 1000;
}

function wordBytes(word) {
	return [word % 256, Math.floor(word / 256)];
}

function bytesWord(bytes) {
	return bytes[1] * 256 + bytes[0];
}


function randomPassword() {
	var pass = PassPhraseGenerator;
	pass.generatePassPhrase();
	$("#nxtbridge-newpassphrase").val(pass.passPhrase);
}

function genAccount($manual) {
	var secretPhrase;
	secretPhrase = $("#nxtbridge-newpassphrase").val();

	var pubKeyStr = converters.byteArrayToHexString(getPublicKey(secretPhrase));
	$("#publickey").val(pubKeyStr);

	var newAcc = getAccountIdFromPublicKey(pubKeyStr, true);
	$("#account").val(newAcc);

	$("#qrcode2").html("");
}

$("#sign").click(function () {

});
