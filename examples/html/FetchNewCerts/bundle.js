var ctBundle = (function (exports) {
'use strict';

//**************************************************************************************
/**
 * Making UTC date from local date
 * @param {Date} date Date to convert from
 * @returns {Date}
 */

//**************************************************************************************
/**
 * Get value for input parameters, or set a default value
 * @param {Object} parameters
 * @param {string} name
 * @param defaultValue
 */
function getParametersValue(parameters, name, defaultValue)
{
	if((parameters instanceof Object) === false)
		return defaultValue;
	
	if(name in parameters)
		return parameters[name];
	
	return defaultValue;
}
//**************************************************************************************
/**
 * Converts "ArrayBuffer" into a hexdecimal string
 * @param {ArrayBuffer} inputBuffer
 * @param {number} [inputOffset=0]
 * @param {number} [inputLength=inputBuffer.byteLength]
 * @returns {string}
 */
function bufferToHexCodes(inputBuffer, inputOffset = 0, inputLength = (inputBuffer.byteLength - inputOffset))
{
	let result = "";
	
	for(const item of (new Uint8Array(inputBuffer, inputOffset, inputLength)))
	{
		const str = item.toString(16).toUpperCase();
		result = result + ((str.length === 1) ? "0" : "") + str;
	}
	
	return result;
}
//**************************************************************************************
/**
 * Check input "ArrayBuffer" for common functions
 * @param {LocalBaseBlock} baseBlock
 * @param {ArrayBuffer} inputBuffer
 * @param {number} inputOffset
 * @param {number} inputLength
 * @returns {boolean}
 */
function checkBufferParams(baseBlock, inputBuffer, inputOffset, inputLength)
{
	if((inputBuffer instanceof ArrayBuffer) === false)
	{
		baseBlock.error = "Wrong parameter: inputBuffer must be \"ArrayBuffer\"";
		return false;
	}
	
	if(inputBuffer.byteLength === 0)
	{
		baseBlock.error = "Wrong parameter: inputBuffer has zero length";
		return false;
	}
	
	if(inputOffset < 0)
	{
		baseBlock.error = "Wrong parameter: inputOffset less than zero";
		return false;
	}
	
	if(inputLength < 0)
	{
		baseBlock.error = "Wrong parameter: inputLength less than zero";
		return false;
	}
	
	if((inputBuffer.byteLength - inputOffset - inputLength) < 0)
	{
		baseBlock.error = "End of input reached before message was fully decoded (inconsistent offset and length values)";
		return false;
	}
	
	return true;
}
//**************************************************************************************
/**
 * Convert number from 2^base to 2^10
 * @param {Uint8Array} inputBuffer
 * @param {number} inputBase
 * @returns {number}
 */
function utilFromBase(inputBuffer, inputBase)
{
	let result = 0;
	
	if(inputBuffer.length === 1)
		return inputBuffer[0];
	
	for(let i = (inputBuffer.length - 1); i >= 0; i--)
		result += inputBuffer[(inputBuffer.length - 1) - i] * Math.pow(2, inputBase * i);
	
	return result;
}
//**************************************************************************************
/**
 * Convert number from 2^10 to 2^base
 * @param {!number} value The number to convert
 * @param {!number} base The base for 2^base
 * @param {number} [reserved=0] Pre-defined number of bytes in output array (-1 = limited by function itself)
 * @returns {ArrayBuffer}
 */
function utilToBase(value, base, reserved = (-1))
{
	const internalReserved = reserved;
	let internalValue = value;
	
	let result = 0;
	let biggest = Math.pow(2, base);
	
	for(let i = 1; i < 8; i++)
	{
		if(value < biggest)
		{
			let retBuf;
			
			if(internalReserved < 0)
			{
				retBuf = new ArrayBuffer(i);
				result = i;
			}
			else
			{
				if(internalReserved < i)
					return (new ArrayBuffer(0));
				
				retBuf = new ArrayBuffer(internalReserved);
				
				result = internalReserved;
			}
			
			const retView = new Uint8Array(retBuf);
			
			for(let j = (i - 1); j >= 0; j--)
			{
				const basis = Math.pow(2, j * base);
				
				retView[result - j - 1] = Math.floor(internalValue / basis);
				internalValue -= (retView[result - j - 1]) * basis;
			}
			
			return retBuf;
		}
		
		biggest *= Math.pow(2, base);
	}
	
	return new ArrayBuffer(0);
}
//**************************************************************************************
/**
 * Concatenate two ArrayBuffers
 * @param {...ArrayBuffer} buffers Set of ArrayBuffer
 */
function utilConcatBuf(...buffers)
{
	//region Initial variables
	let outputLength = 0;
	let prevLength = 0;
	//endregion
	
	//region Calculate output length
	
	for(const buffer of buffers)
		outputLength += buffer.byteLength;
	//endregion
	
	const retBuf = new ArrayBuffer(outputLength);
	const retView = new Uint8Array(retBuf);
	
	for(const buffer of buffers)
	{
		retView.set(new Uint8Array(buffer), prevLength);
		prevLength += buffer.byteLength;
	}
	
	return retBuf;
}
//**************************************************************************************
/**
 * Concatenate two Uint8Array
 * @param {...Uint8Array} views Set of Uint8Array
 */
function utilConcatView(...views)
{
	//region Initial variables
	let outputLength = 0;
	let prevLength = 0;
	//endregion
	
	//region Calculate output length
	for(const view of views)
		outputLength += view.length;
	//endregion
	
	const retBuf = new ArrayBuffer(outputLength);
	const retView = new Uint8Array(retBuf);
	
	for(const view of views)
	{
		retView.set(view, prevLength);
		prevLength += view.length;
	}
	
	return retView;
}
//**************************************************************************************
/**
 * Decoding of "two complement" values
 * The function must be called in scope of instance of "hexBlock" class ("valueHex" and "warnings" properties must be present)
 * @returns {number}
 */
function utilDecodeTC()
{
	const buf = new Uint8Array(this.valueHex);
	
	if(this.valueHex.byteLength >= 2)
	{
		//noinspection JSBitwiseOperatorUsage
		const condition1 = (buf[0] === 0xFF) && (buf[1] & 0x80);
		const condition2 = (buf[0] === 0x00) && ((buf[1] & 0x80) === 0x00);
		
		if(condition1 || condition2)
			this.warnings.push("Needlessly long format");
	}
	
	//region Create big part of the integer
	const bigIntBuffer = new ArrayBuffer(this.valueHex.byteLength);
	const bigIntView = new Uint8Array(bigIntBuffer);
	for(let i = 0; i < this.valueHex.byteLength; i++)
		bigIntView[i] = 0;
	
	bigIntView[0] = (buf[0] & 0x80); // mask only the biggest bit
	
	const bigInt = utilFromBase(bigIntView, 8);
	//endregion
	
	//region Create small part of the integer
	const smallIntBuffer = new ArrayBuffer(this.valueHex.byteLength);
	const smallIntView = new Uint8Array(smallIntBuffer);
	for(let j = 0; j < this.valueHex.byteLength; j++)
		smallIntView[j] = buf[j];
	
	smallIntView[0] &= 0x7F; // mask biggest bit
	
	const smallInt = utilFromBase(smallIntView, 8);
	//endregion
	
	return (smallInt - bigInt);
}
//**************************************************************************************
/**
 * Encode integer value to "two complement" format
 * @param {number} value Value to encode
 * @returns {ArrayBuffer}
 */
function utilEncodeTC(value)
{
	const modValue = (value < 0) ? (value * (-1)) : value;
	let bigInt = 128;
	
	for(let i = 1; i < 8; i++)
	{
		if(modValue <= bigInt)
		{
			if(value < 0)
			{
				const smallInt = bigInt - modValue;
				
				const retBuf = utilToBase(smallInt, 8, i);
				const retView = new Uint8Array(retBuf);
				
				retView[0] |= 0x80;
				
				return retBuf;
			}
			
			let retBuf = utilToBase(modValue, 8, i);
			let retView = new Uint8Array(retBuf);
			
			//noinspection JSBitwiseOperatorUsage
			if(retView[0] & 0x80)
			{
				//noinspection JSCheckFunctionSignatures
				const tempBuf = retBuf.slice(0);
				const tempView = new Uint8Array(tempBuf);
				
				retBuf = new ArrayBuffer(retBuf.byteLength + 1);
				retView = new Uint8Array(retBuf);
				
				for(let k = 0; k < tempBuf.byteLength; k++)
					retView[k + 1] = tempView[k];
				
				retView[0] = 0x00;
			}
			
			return retBuf;
		}
		
		bigInt *= Math.pow(2, 8);
	}
	
	return (new ArrayBuffer(0));
}
//**************************************************************************************
/**
 * Compare two array buffers
 * @param {!ArrayBuffer} inputBuffer1
 * @param {!ArrayBuffer} inputBuffer2
 * @returns {boolean}
 */
function isEqualBuffer(inputBuffer1, inputBuffer2)
{
	if(inputBuffer1.byteLength !== inputBuffer2.byteLength)
		return false;
	
	const view1 = new Uint8Array(inputBuffer1);
	const view2 = new Uint8Array(inputBuffer2);
	
	for(let i = 0; i < view1.length; i++)
	{
		if(view1[i] !== view2[i])
			return false;
	}
	
	return true;
}
//**************************************************************************************
/**
 * Pad input number with leade "0" if needed
 * @returns {string}
 * @param {number} inputNumber
 * @param {number} fullLength
 */
function padNumber(inputNumber, fullLength)
{
	const str = inputNumber.toString(10);
	
	if(fullLength < str.length)
		return "";
	
	const dif = fullLength - str.length;
	
	const padding = new Array(dif);
	for(let i = 0; i < dif; i++)
		padding[i] = "0";
	
	const paddingString = padding.join("");
	
	return paddingString.concat(str);
}
//**************************************************************************************
const base64Template = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const base64UrlTemplate = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=";
//**************************************************************************************
/**
 * Encode string into BASE64 (or "base64url")
 * @param {string} input
 * @param {boolean} useUrlTemplate If "true" then output would be encoded using "base64url"
 * @param {boolean} skipPadding Skip BASE-64 padding or not
 * @param {boolean} skipLeadingZeros Skip leading zeros in input data or not
 * @returns {string}
 */
function toBase64(input, useUrlTemplate = false, skipPadding = false, skipLeadingZeros = false)
{
	let i = 0;
	
	let flag1 = 0;
	let flag2 = 0;
	
	let output = "";
	
	const template = (useUrlTemplate) ? base64UrlTemplate : base64Template;
	
	if(skipLeadingZeros)
	{
		let nonZeroPosition = 0;
		
		for(let i = 0; i < input.length; i++)
		{
			if(input.charCodeAt(i) !== 0)
			{
				nonZeroPosition = i;
				break;
			}
		}
		
		input = input.slice(nonZeroPosition);
	}
	
	while(i < input.length)
	{
		const chr1 = input.charCodeAt(i++);
		if(i >= input.length)
			flag1 = 1;
		const chr2 = input.charCodeAt(i++);
		if(i >= input.length)
			flag2 = 1;
		const chr3 = input.charCodeAt(i++);
		
		const enc1 = chr1 >> 2;
		const enc2 = ((chr1 & 0x03) << 4) | (chr2 >> 4);
		let enc3 = ((chr2 & 0x0F) << 2) | (chr3 >> 6);
		let enc4 = chr3 & 0x3F;
		
		if(flag1 === 1)
			enc3 = enc4 = 64;
		else
		{
			if(flag2 === 1)
				enc4 = 64;
		}
		
		if(skipPadding)
		{
			if(enc3 === 64)
				output += `${template.charAt(enc1)}${template.charAt(enc2)}`;
			else
			{
				if(enc4 === 64)
					output += `${template.charAt(enc1)}${template.charAt(enc2)}${template.charAt(enc3)}`;
				else
					output += `${template.charAt(enc1)}${template.charAt(enc2)}${template.charAt(enc3)}${template.charAt(enc4)}`;
			}
		}
		else
			output += `${template.charAt(enc1)}${template.charAt(enc2)}${template.charAt(enc3)}${template.charAt(enc4)}`;
	}
	
	return output;
}
//**************************************************************************************
/**
 * Decode string from BASE64 (or "base64url")
 * @param {string} input
 * @param {boolean} [useUrlTemplate=false] If "true" then output would be encoded using "base64url"
 * @param {boolean} [cutTailZeros=false] If "true" then cut tailing zeroz from function result
 * @returns {string}
 */
function fromBase64(input, useUrlTemplate = false, cutTailZeros = false)
{
	const template = (useUrlTemplate) ? base64UrlTemplate : base64Template;
	
	//region Aux functions
	function indexof(toSearch)
	{
		for(let i = 0; i < 64; i++)
		{
			if(template.charAt(i) === toSearch)
				return i;
		}
		
		return 64;
	}
	
	function test(incoming)
	{
		return ((incoming === 64) ? 0x00 : incoming);
	}
	//endregion
	
	let i = 0;
	
	let output = "";
	
	while(i < input.length)
	{
		const enc1 = indexof(input.charAt(i++));
		const enc2 = (i >= input.length) ? 0x00 : indexof(input.charAt(i++));
		const enc3 = (i >= input.length) ? 0x00 : indexof(input.charAt(i++));
		const enc4 = (i >= input.length) ? 0x00 : indexof(input.charAt(i++));
		
		const chr1 = (test(enc1) << 2) | (test(enc2) >> 4);
		const chr2 = ((test(enc2) & 0x0F) << 4) | (test(enc3) >> 2);
		const chr3 = ((test(enc3) & 0x03) << 6) | test(enc4);
		
		output += String.fromCharCode(chr1);
		
		if(enc3 !== 64)
			output += String.fromCharCode(chr2);
		
		if(enc4 !== 64)
			output += String.fromCharCode(chr3);
	}
	
	if(cutTailZeros)
	{
		const outputLength = output.length;
		let nonZeroStart = (-1);
		
		for(let i = (outputLength - 1); i >= 0; i--)
		{
			if(output.charCodeAt(i) !== 0)
			{
				nonZeroStart = i;
				break;
			}
		}
		
		if(nonZeroStart !== (-1))
			output = output.slice(0, nonZeroStart + 1);
		else
			output = "";
	}
	
	return output;
}
//**************************************************************************************
function arrayBufferToString(buffer)
{
	let resultString = "";
	const view = new Uint8Array(buffer);
	
	for(const element of view)
		resultString = resultString + String.fromCharCode(element);
	
	return resultString;
}
//**************************************************************************************
function stringToArrayBuffer(str)
{
	const stringLength = str.length;
	
	const resultBuffer = new ArrayBuffer(stringLength);
	const resultView = new Uint8Array(resultBuffer);
	
	for(let i = 0; i < stringLength; i++)
		resultView[i] = str.charCodeAt(i);
	
	return resultBuffer;
}
//**************************************************************************************
const log2 = Math.log(2);
//**************************************************************************************
/**
 * Get nearest to input length power of 2
 * @param {number} length Current length of existing array
 * @returns {number}
 */
function nearestPowerOf2(length)
{
	const base = (Math.log(length) / log2);
	
	const floor = Math.floor(base);
	const round = Math.round(base);
	
	return ((floor === round) ? floor : round);
}
//**************************************************************************************

/*
 * Copyright (c) 2016, Peculiar Ventures
 * All rights reserved.
 *
 * Author 2016, Yury Strozhevsky <www.strozhevsky.com>.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 */
//**************************************************************************************
const powers2 = [new Uint8Array([1])];
const digitsString = "0123456789";
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration for "LocalBaseBlock" class
//**************************************************************************************
/**
 * Class used as a base block for all remaining ASN.1 classes
 * @typedef LocalBaseBlock
 * @interface
 * @property {number} blockLength
 * @property {string} error
 * @property {Array.<string>} warnings
 * @property {ArrayBuffer} valueBeforeDecode
 */
class LocalBaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalBaseBlock" class
	 * @param {Object} [parameters={}]
	 * @property {ArrayBuffer} [valueBeforeDecode]
	 */
	constructor(parameters = {})
	{
		/**
		 * @type {number} blockLength
		 */
		this.blockLength = getParametersValue(parameters, "blockLength", 0);
		/**
		 * @type {string} error
		 */
		this.error = getParametersValue(parameters, "error", "");
		/**
		 * @type {Array.<string>} warnings
		 */
		this.warnings = getParametersValue(parameters, "warnings", []);
		//noinspection JSCheckFunctionSignatures
		/**
		 * @type {ArrayBuffer} valueBeforeDecode
		 */
		if("valueBeforeDecode" in parameters)
			this.valueBeforeDecode = parameters.valueBeforeDecode.slice(0);
		else
			this.valueBeforeDecode = new ArrayBuffer(0);
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "baseBlock";
	}
	//**********************************************************************************
	/**
	 * Convertion for the block to JSON object
	 * @returns {{blockName: string, blockLength: number, error: string, warnings: Array.<string>, valueBeforeDecode: string}}
	 */
	toJSON()
	{
		return {
			blockName: this.constructor.blockName(),
			blockLength: this.blockLength,
			error: this.error,
			warnings: this.warnings,
			valueBeforeDecode: bufferToHexCodes(this.valueBeforeDecode, 0, this.valueBeforeDecode.byteLength)
		};
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Description for "LocalHexBlock" class
//**************************************************************************************
/**
 * Class used as a base block for all remaining ASN.1 classes
 * @extends LocalBaseBlock
 * @typedef LocalHexBlock
 * @property {number} blockLength
 * @property {string} error
 * @property {Array.<string>} warnings
 * @property {ArrayBuffer} valueBeforeDecode
 * @property {boolean} isHexOnly
 * @property {ArrayBuffer} valueHex
 */
//noinspection JSUnusedLocalSymbols
const LocalHexBlock = BaseClass => class LocalHexBlockMixin extends BaseClass
{
	//**********************************************************************************
	//noinspection JSUnusedGlobalSymbols
	/**
	 * Constructor for "LocalHexBlock" class
	 * @param {Object} [parameters={}]
	 * @property {ArrayBuffer} [valueHex]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		/**
		 * @type {boolean}
		 */
		this.isHexOnly = getParametersValue(parameters, "isHexOnly", false);
		/**
		 * @type {ArrayBuffer}
		 */
		if("valueHex" in parameters)
			this.valueHex = parameters.valueHex.slice(0);
		else
			this.valueHex = new ArrayBuffer(0);
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "hexBlock";
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		//region Basic check for parameters
		//noinspection JSCheckFunctionSignatures
		if(checkBufferParams(this, inputBuffer, inputOffset, inputLength) === false)
			return (-1);
		//endregion

		//region Getting Uint8Array from ArrayBuffer
		const intBuffer = new Uint8Array(inputBuffer, inputOffset, inputLength);
		//endregion

		//region Initial checks
		if(intBuffer.length === 0)
		{
			this.warnings.push("Zero buffer length");
			return inputOffset;
		}
		//endregion

		//region Copy input buffer to internal buffer
		this.valueHex = inputBuffer.slice(inputOffset, inputOffset + inputLength);
		//endregion

		this.blockLength = inputLength;

		return (inputOffset + inputLength);
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		if(this.isHexOnly !== true)
		{
			this.error = "Flag \"isHexOnly\" is not set, abort";
			return new ArrayBuffer(0);
		}

		if(sizeOnly === true)
			return new ArrayBuffer(this.valueHex.byteLength);

		//noinspection JSCheckFunctionSignatures
		return this.valueHex.slice(0);
	}
	//**********************************************************************************
	/**
	 * Convertion for the block to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.blockName = this.constructor.blockName();
		object.isHexOnly = this.isHexOnly;
		object.valueHex = bufferToHexCodes(this.valueHex, 0, this.valueHex.byteLength);

		return object;
	}
	//**********************************************************************************
};
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of identification block class
//**************************************************************************************
class LocalIdentificationBlock extends LocalHexBlock(LocalBaseBlock)
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalBaseBlock" class
	 * @param {Object} [parameters={}]
	 * @property {Object} [idBlock]
	 */
	constructor(parameters = {})
	{
		super();

		if("idBlock" in parameters)
		{
			//region Properties from hexBlock class
			this.isHexOnly = getParametersValue(parameters.idBlock, "isHexOnly", false);
			this.valueHex = getParametersValue(parameters.idBlock, "valueHex", new ArrayBuffer(0));
			//endregion

			this.tagClass = getParametersValue(parameters.idBlock, "tagClass", (-1));
			this.tagNumber = getParametersValue(parameters.idBlock, "tagNumber", (-1));
			this.isConstructed = getParametersValue(parameters.idBlock, "isConstructed", false);
		}
		else
		{
			this.tagClass = (-1);
			this.tagNumber = (-1);
			this.isConstructed = false;
		}
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "identificationBlock";
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		//region Initial variables
		let firstOctet = 0;
		let retBuf;
		let retView;
		//endregion

		switch(this.tagClass)
		{
			case 1:
				firstOctet |= 0x00; // UNIVERSAL
				break;
			case 2:
				firstOctet |= 0x40; // APPLICATION
				break;
			case 3:
				firstOctet |= 0x80; // CONTEXT-SPECIFIC
				break;
			case 4:
				firstOctet |= 0xC0; // PRIVATE
				break;
			default:
				this.error = "Unknown tag class";
				return (new ArrayBuffer(0));
		}

		if(this.isConstructed)
			firstOctet |= 0x20;

		if((this.tagNumber < 31) && (!this.isHexOnly))
		{
			retBuf = new ArrayBuffer(1);
			retView = new Uint8Array(retBuf);

			if(!sizeOnly)
			{
				let number = this.tagNumber;
				number &= 0x1F;
				firstOctet |= number;

				retView[0] = firstOctet;
			}

			return retBuf;
		}

		if(this.isHexOnly === false)
		{
			const encodedBuf = utilToBase(this.tagNumber, 7);
			const encodedView = new Uint8Array(encodedBuf);
			const size = encodedBuf.byteLength;

			retBuf = new ArrayBuffer(size + 1);
			retView = new Uint8Array(retBuf);
			retView[0] = (firstOctet | 0x1F);

			if(!sizeOnly)
			{
				for(let i = 0; i < (size - 1); i++)
					retView[i + 1] = encodedView[i] | 0x80;

				retView[size] = encodedView[size - 1];
			}

			return retBuf;
		}

		retBuf = new ArrayBuffer(this.valueHex.byteLength + 1);
		retView = new Uint8Array(retBuf);

		retView[0] = (firstOctet | 0x1F);

		if(sizeOnly === false)
		{
			const curView = new Uint8Array(this.valueHex);

			for(let i = 0; i < (curView.length - 1); i++)
				retView[i + 1] = curView[i] | 0x80;

			retView[this.valueHex.byteLength] = curView[curView.length - 1];
		}

		return retBuf;
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number}
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		//region Basic check for parameters
		//noinspection JSCheckFunctionSignatures
		if(checkBufferParams(this, inputBuffer, inputOffset, inputLength) === false)
			return (-1);
		//endregion

		//region Getting Uint8Array from ArrayBuffer
		const intBuffer = new Uint8Array(inputBuffer, inputOffset, inputLength);
		//endregion

		//region Initial checks
		if(intBuffer.length === 0)
		{
			this.error = "Zero buffer length";
			return (-1);
		}
		//endregion

		//region Find tag class
		const tagClassMask = intBuffer[0] & 0xC0;

		switch(tagClassMask)
		{
			case 0x00:
				this.tagClass = (1); // UNIVERSAL
				break;
			case 0x40:
				this.tagClass = (2); // APPLICATION
				break;
			case 0x80:
				this.tagClass = (3); // CONTEXT-SPECIFIC
				break;
			case 0xC0:
				this.tagClass = (4); // PRIVATE
				break;
			default:
				this.error = "Unknown tag class";
				return (-1);
		}
		//endregion

		//region Find it's constructed or not
		this.isConstructed = (intBuffer[0] & 0x20) === 0x20;
		//endregion

		//region Find tag number
		this.isHexOnly = false;

		const tagNumberMask = intBuffer[0] & 0x1F;

		//region Simple case (tag number < 31)
		if(tagNumberMask !== 0x1F)
		{
			this.tagNumber = (tagNumberMask);
			this.blockLength = 1;
		}
		//endregion
		//region Tag number bigger or equal to 31
		else
		{
			let count = 1;

			this.valueHex = new ArrayBuffer(255);
			let tagNumberBufferMaxLength = 255;
			let intTagNumberBuffer = new Uint8Array(this.valueHex);

			//noinspection JSBitwiseOperatorUsage
			while(intBuffer[count] & 0x80)
			{
				intTagNumberBuffer[count - 1] = intBuffer[count] & 0x7F;
				count++;

				if(count >= intBuffer.length)
				{
					this.error = "End of input reached before message was fully decoded";
					return (-1);
				}

				//region In case if tag number length is greater than 255 bytes (rare but possible case)
				if(count === tagNumberBufferMaxLength)
				{
					tagNumberBufferMaxLength += 255;

					const tempBuffer = new ArrayBuffer(tagNumberBufferMaxLength);
					const tempBufferView = new Uint8Array(tempBuffer);

					for(let i = 0; i < intTagNumberBuffer.length; i++)
						tempBufferView[i] = intTagNumberBuffer[i];

					this.valueHex = new ArrayBuffer(tagNumberBufferMaxLength);
					intTagNumberBuffer = new Uint8Array(this.valueHex);
				}
				//endregion
			}

			this.blockLength = (count + 1);
			intTagNumberBuffer[count - 1] = intBuffer[count] & 0x7F; // Write last byte to buffer

			//region Cut buffer
			const tempBuffer = new ArrayBuffer(count);
			const tempBufferView = new Uint8Array(tempBuffer);

			for(let i = 0; i < count; i++)
				tempBufferView[i] = intTagNumberBuffer[i];

			this.valueHex = new ArrayBuffer(count);
			intTagNumberBuffer = new Uint8Array(this.valueHex);
			intTagNumberBuffer.set(tempBufferView);
			//endregion

			//region Try to convert long tag number to short form
			if(this.blockLength <= 9)
				this.tagNumber = utilFromBase(intTagNumberBuffer, 7);
			else
			{
				this.isHexOnly = true;
				this.warnings.push("Tag too long, represented as hex-coded");
			}
			//endregion
		}
		//endregion
		//endregion

		//region Check if constructed encoding was using for primitive type
		if(((this.tagClass === 1)) &&
			(this.isConstructed))
		{
			switch(this.tagNumber)
			{
				case 1:  // Boolean
				case 2:  // REAL
				case 5:  // Null
				case 6:  // OBJECT IDENTIFIER
				case 9:  // REAL
				case 14: // Time
				case 23:
				case 24:
				case 31:
				case 32:
				case 33:
				case 34:
					this.error = "Constructed encoding used for primitive type";
					return (-1);
				default:
			}
		}
		//endregion

		return (inputOffset + this.blockLength); // Return current offset in input buffer
	}
	//**********************************************************************************
	/**
	 * Convertion for the block to JSON object
	 * @returns {{blockName: string,
	 *  tagClass: number,
	 *  tagNumber: number,
	 *  isConstructed: boolean,
	 *  isHexOnly: boolean,
	 *  valueHex: ArrayBuffer,
	 *  blockLength: number,
	 *  error: string, warnings: Array.<string>,
	 *  valueBeforeDecode: string}}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.blockName = this.constructor.blockName();
		object.tagClass = this.tagClass;
		object.tagNumber = this.tagNumber;
		object.isConstructed = this.isConstructed;

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of length block class
//**************************************************************************************
class LocalLengthBlock extends LocalBaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalLengthBlock" class
	 * @param {Object} [parameters={}]
	 * @property {Object} [lenBlock]
	 */
	constructor(parameters = {})
	{
		super();

		if("lenBlock" in parameters)
		{
			this.isIndefiniteForm = getParametersValue(parameters.lenBlock, "isIndefiniteForm", false);
			this.longFormUsed = getParametersValue(parameters.lenBlock, "longFormUsed", false);
			this.length = getParametersValue(parameters.lenBlock, "length", 0);
		}
		else
		{
			this.isIndefiniteForm = false;
			this.longFormUsed = false;
			this.length = 0;
		}
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "lengthBlock";
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number}
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		//region Basic check for parameters
		//noinspection JSCheckFunctionSignatures
		if(checkBufferParams(this, inputBuffer, inputOffset, inputLength) === false)
			return (-1);
		//endregion

		//region Getting Uint8Array from ArrayBuffer
		const intBuffer = new Uint8Array(inputBuffer, inputOffset, inputLength);
		//endregion

		//region Initial checks
		if(intBuffer.length === 0)
		{
			this.error = "Zero buffer length";
			return (-1);
		}

		if(intBuffer[0] === 0xFF)
		{
			this.error = "Length block 0xFF is reserved by standard";
			return (-1);
		}
		//endregion

		//region Check for length form type
		this.isIndefiniteForm = intBuffer[0] === 0x80;
		//endregion

		//region Stop working in case of indefinite length form
		if(this.isIndefiniteForm === true)
		{
			this.blockLength = 1;
			return (inputOffset + this.blockLength);
		}
		//endregion

		//region Check is long form of length encoding using
		this.longFormUsed = !!(intBuffer[0] & 0x80);
		//endregion

		//region Stop working in case of short form of length value
		if(this.longFormUsed === false)
		{
			this.length = (intBuffer[0]);
			this.blockLength = 1;
			return (inputOffset + this.blockLength);
		}
		//endregion

		//region Calculate length value in case of long form
		const count = intBuffer[0] & 0x7F;

		if(count > 8) // Too big length value
		{
			this.error = "Too big integer";
			return (-1);
		}

		if((count + 1) > intBuffer.length)
		{
			this.error = "End of input reached before message was fully decoded";
			return (-1);
		}

		const lengthBufferView = new Uint8Array(count);

		for(let i = 0; i < count; i++)
			lengthBufferView[i] = intBuffer[i + 1];

		if(lengthBufferView[count - 1] === 0x00)
			this.warnings.push("Needlessly long encoded length");

		this.length = utilFromBase(lengthBufferView, 8);

		if(this.longFormUsed && (this.length <= 127))
			this.warnings.push("Unneccesary usage of long length form");

		this.blockLength = count + 1;
		//endregion

		return (inputOffset + this.blockLength); // Return current offset in input buffer
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		//region Initial variables
		let retBuf;
		let retView;
		//endregion

		if(this.length > 127)
			this.longFormUsed = true;

		if(this.isIndefiniteForm)
		{
			retBuf = new ArrayBuffer(1);

			if(sizeOnly === false)
			{
				retView = new Uint8Array(retBuf);
				retView[0] = 0x80;
			}

			return retBuf;
		}

		if(this.longFormUsed === true)
		{
			const encodedBuf = utilToBase(this.length, 8);

			if(encodedBuf.byteLength > 127)
			{
				this.error = "Too big length";
				return (new ArrayBuffer(0));
			}

			retBuf = new ArrayBuffer(encodedBuf.byteLength + 1);

			if(sizeOnly === true)
				return retBuf;

			const encodedView = new Uint8Array(encodedBuf);
			retView = new Uint8Array(retBuf);

			retView[0] = encodedBuf.byteLength | 0x80;

			for(let i = 0; i < encodedBuf.byteLength; i++)
				retView[i + 1] = encodedView[i];

			return retBuf;
		}

		retBuf = new ArrayBuffer(1);

		if(sizeOnly === false)
		{
			retView = new Uint8Array(retBuf);

			retView[0] = this.length;
		}

		return retBuf;
	}
	//**********************************************************************************
	/**
	 * Convertion for the block to JSON object
	 * @returns {{blockName, blockLength, error, warnings, valueBeforeDecode}|{blockName: string, blockLength: number, error: string, warnings: Array.<string>, valueBeforeDecode: string}}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.blockName = this.constructor.blockName();
		object.isIndefiniteForm = this.isIndefiniteForm;
		object.longFormUsed = this.longFormUsed;
		object.length = this.length;

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of value block class
//**************************************************************************************
class LocalValueBlock extends LocalBaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalValueBlock" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "valueBlock";
	}
	//**********************************************************************************
	//noinspection JSUnusedLocalSymbols,JSUnusedLocalSymbols,JSUnusedLocalSymbols
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number}
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		//region Throw an exception for a function which needs to be specified in extended classes
		throw TypeError("User need to make a specific function in a class which extends \"LocalValueBlock\"");
		//endregion
	}
	//**********************************************************************************
	//noinspection JSUnusedLocalSymbols
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		//region Throw an exception for a function which needs to be specified in extended classes
		throw TypeError("User need to make a specific function in a class which extends \"LocalValueBlock\"");
		//endregion
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of basic ASN.1 block class
//**************************************************************************************
class BaseBlock extends LocalBaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "BaseBlock" class
	 * @param {Object} [parameters={}]
	 * @property {Object} [primitiveSchema]
	 * @property {string} [name]
	 * @property {boolean} [optional]
	 * @param valueBlockType Type of value block
	 */
	constructor(parameters = {}, valueBlockType = LocalValueBlock)
	{
		super(parameters);

		if("name" in parameters)
			this.name = parameters.name;
		if("optional" in parameters)
			this.optional = parameters.optional;
		if("primitiveSchema" in parameters)
			this.primitiveSchema = parameters.primitiveSchema;

		this.idBlock = new LocalIdentificationBlock(parameters);
		this.lenBlock = new LocalLengthBlock(parameters);
		this.valueBlock = new valueBlockType(parameters);
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "BaseBlock";
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number}
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		const resultOffset = this.valueBlock.fromBER(inputBuffer, inputOffset, (this.lenBlock.isIndefiniteForm === true) ? inputLength : this.lenBlock.length);
		if(resultOffset === (-1))
		{
			this.error = this.valueBlock.error;
			return resultOffset;
		}

		if(this.idBlock.error.length === 0)
			this.blockLength += this.idBlock.blockLength;

		if(this.lenBlock.error.length === 0)
			this.blockLength += this.lenBlock.blockLength;

		if(this.valueBlock.error.length === 0)
			this.blockLength += this.valueBlock.blockLength;

		return resultOffset;
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		let retBuf;

		const idBlockBuf = this.idBlock.toBER(sizeOnly);
		const valueBlockSizeBuf = this.valueBlock.toBER(true);

		this.lenBlock.length = valueBlockSizeBuf.byteLength;
		const lenBlockBuf = this.lenBlock.toBER(sizeOnly);

		retBuf = utilConcatBuf(idBlockBuf, lenBlockBuf);

		let valueBlockBuf;

		if(sizeOnly === false)
			valueBlockBuf = this.valueBlock.toBER(sizeOnly);
		else
			valueBlockBuf = new ArrayBuffer(this.lenBlock.length);

		retBuf = utilConcatBuf(retBuf, valueBlockBuf);

		if(this.lenBlock.isIndefiniteForm === true)
		{
			const indefBuf = new ArrayBuffer(2);

			if(sizeOnly === false)
			{
				const indefView = new Uint8Array(indefBuf);

				indefView[0] = 0x00;
				indefView[1] = 0x00;
			}

			retBuf = utilConcatBuf(retBuf, indefBuf);
		}

		return retBuf;
	}
	//**********************************************************************************
	/**
	 * Convertion for the block to JSON object
	 * @returns {{blockName, blockLength, error, warnings, valueBeforeDecode}|{blockName: string, blockLength: number, error: string, warnings: Array.<string>, valueBeforeDecode: string}}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.idBlock = this.idBlock.toJSON();
		object.lenBlock = this.lenBlock.toJSON();
		object.valueBlock = this.valueBlock.toJSON();

		if("name" in this)
			object.name = this.name;
		if("optional" in this)
			object.optional = this.optional;
		if("primitiveSchema" in this)
			object.primitiveSchema = this.primitiveSchema.toJSON();

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of basic block for all PRIMITIVE types
//**************************************************************************************
class LocalPrimitiveValueBlock extends LocalValueBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalPrimitiveValueBlock" class
	 * @param {Object} [parameters={}]
	 * @property {ArrayBuffer} [valueBeforeDecode]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		//region Variables from "hexBlock" class
		if("valueHex" in parameters)
			this.valueHex = parameters.valueHex.slice(0);
		else
			this.valueHex = new ArrayBuffer(0);

		this.isHexOnly = getParametersValue(parameters, "isHexOnly", true);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number}
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		//region Basic check for parameters
		//noinspection JSCheckFunctionSignatures
		if(checkBufferParams(this, inputBuffer, inputOffset, inputLength) === false)
			return (-1);
		//endregion

		//region Getting Uint8Array from ArrayBuffer
		const intBuffer = new Uint8Array(inputBuffer, inputOffset, inputLength);
		//endregion

		//region Initial checks
		if(intBuffer.length === 0)
		{
			this.warnings.push("Zero buffer length");
			return inputOffset;
		}
		//endregion

		//region Copy input buffer into internal buffer
		this.valueHex = new ArrayBuffer(intBuffer.length);
		const valueHexView = new Uint8Array(this.valueHex);

		for(let i = 0; i < intBuffer.length; i++)
			valueHexView[i] = intBuffer[i];
		//endregion

		this.blockLength = inputLength;

		return (inputOffset + inputLength);
	}
	//**********************************************************************************
	//noinspection JSUnusedLocalSymbols
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		return this.valueHex.slice(0);
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "PrimitiveValueBlock";
	}
	//**********************************************************************************
	/**
	 * Convertion for the block to JSON object
	 * @returns {{blockName, blockLength, error, warnings, valueBeforeDecode}|{blockName: string, blockLength: number, error: string, warnings: Array.<string>, valueBeforeDecode: string}}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.valueHex = bufferToHexCodes(this.valueHex, 0, this.valueHex.byteLength);
		object.isHexOnly = this.isHexOnly;

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
class Primitive extends BaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "Primitive" class
	 * @param {Object} [parameters={}]
	 * @property {ArrayBuffer} [valueHex]
	 */
	constructor(parameters = {})
	{
		super(parameters, LocalPrimitiveValueBlock);

		this.idBlock.isConstructed = false;
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "PRIMITIVE";
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of basic block for all CONSTRUCTED types
//**************************************************************************************
class LocalConstructedValueBlock extends LocalValueBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalConstructedValueBlock" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.value = getParametersValue(parameters, "value", []);
		this.isIndefiniteForm = getParametersValue(parameters, "isIndefiniteForm", false);
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number}
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		//region Store initial offset and length
		const initialOffset = inputOffset;
		const initialLength = inputLength;
		//endregion

		//region Basic check for parameters
		//noinspection JSCheckFunctionSignatures
		if(checkBufferParams(this, inputBuffer, inputOffset, inputLength) === false)
			return (-1);
		//endregion

		//region Getting Uint8Array from ArrayBuffer
		const intBuffer = new Uint8Array(inputBuffer, inputOffset, inputLength);
		//endregion

		//region Initial checks
		if(intBuffer.length === 0)
		{
			this.warnings.push("Zero buffer length");
			return inputOffset;
		}
		//endregion

		//region Aux function
		function checkLen(indefiniteLength, length)
		{
			if(indefiniteLength === true)
				return 1;

			return length;
		}
		//endregion

		let currentOffset = inputOffset;

		while(checkLen(this.isIndefiniteForm, inputLength) > 0)
		{
			const returnObject = LocalFromBER(inputBuffer, currentOffset, inputLength);
			if(returnObject.offset === (-1))
			{
				this.error = returnObject.result.error;
				this.warnings.concat(returnObject.result.warnings);
				return (-1);
			}

			currentOffset = returnObject.offset;

			this.blockLength += returnObject.result.blockLength;
			inputLength -= returnObject.result.blockLength;

			this.value.push(returnObject.result);

			if((this.isIndefiniteForm === true) && (returnObject.result.constructor.blockName() === EndOfContent.blockName()))
				break;
		}

		if(this.isIndefiniteForm === true)
		{
			if(this.value[this.value.length - 1].constructor.blockName() === EndOfContent.blockName())
				this.value.pop();
			else
				this.warnings.push("No EndOfContent block encoded");
		}

		//region Copy "inputBuffer" to "valueBeforeDecode"
		this.valueBeforeDecode = inputBuffer.slice(initialOffset, initialOffset + initialLength);
		//endregion

		return currentOffset;
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		let retBuf = new ArrayBuffer(0);

		for(let i = 0; i < this.value.length; i++)
		{
			const valueBuf = this.value[i].toBER(sizeOnly);
			retBuf = utilConcatBuf(retBuf, valueBuf);
		}

		return retBuf;
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "ConstructedValueBlock";
	}
	//**********************************************************************************
	/**
	 * Convertion for the block to JSON object
	 * @returns {{blockName, blockLength, error, warnings, valueBeforeDecode}|{blockName: string, blockLength: number, error: string, warnings: Array.<string>, valueBeforeDecode: string}}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.isIndefiniteForm = this.isIndefiniteForm;
		object.value = [];
		for(let i = 0; i < this.value.length; i++)
			object.value.push(this.value[i].toJSON());

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
class Constructed extends BaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "Constructed" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters, LocalConstructedValueBlock);

		this.idBlock.isConstructed = true;
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "CONSTRUCTED";
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number}
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		this.valueBlock.isIndefiniteForm = this.lenBlock.isIndefiniteForm;

		const resultOffset = this.valueBlock.fromBER(inputBuffer, inputOffset, (this.lenBlock.isIndefiniteForm === true) ? inputLength : this.lenBlock.length);
		if(resultOffset === (-1))
		{
			this.error = this.valueBlock.error;
			return resultOffset;
		}

		if(this.idBlock.error.length === 0)
			this.blockLength += this.idBlock.blockLength;

		if(this.lenBlock.error.length === 0)
			this.blockLength += this.lenBlock.blockLength;

		if(this.valueBlock.error.length === 0)
			this.blockLength += this.valueBlock.blockLength;

		return resultOffset;
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of ASN.1 EndOfContent type class
//**************************************************************************************
class LocalEndOfContentValueBlock extends LocalValueBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalEndOfContentValueBlock" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);
	}
	//**********************************************************************************
	//noinspection JSUnusedLocalSymbols,JSUnusedLocalSymbols
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number}
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		//region There is no "value block" for EndOfContent type and we need to return the same offset
		return inputOffset;
		//endregion
	}
	//**********************************************************************************
	//noinspection JSUnusedLocalSymbols
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		return new ArrayBuffer(0);
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "EndOfContentValueBlock";
	}
	//**********************************************************************************
}
//**************************************************************************************
class EndOfContent extends BaseBlock
{
	//**********************************************************************************
	constructor(paramaters = {})
	{
		super(paramaters, LocalEndOfContentValueBlock);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 0; // EndOfContent
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "EndOfContent";
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of ASN.1 Boolean type class
//**************************************************************************************
class LocalBooleanValueBlock extends LocalValueBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalBooleanValueBlock" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);
		
		this.value = getParametersValue(parameters, "value", false);
		this.isHexOnly = getParametersValue(parameters, "isHexOnly", false);
		
		if("valueHex" in parameters)
			this.valueHex = parameters.valueHex.slice(0);
		else
		{
			this.valueHex = new ArrayBuffer(1);
			if(this.value === true)
			{
				var view = new Uint8Array(this.valueHex);
				view[0] = 0xFF;
			}
		}
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		//region Basic check for parameters
		//noinspection JSCheckFunctionSignatures
		if(checkBufferParams(this, inputBuffer, inputOffset, inputLength) === false)
			return (-1);
		//endregion

		//region Getting Uint8Array from ArrayBuffer
		const intBuffer = new Uint8Array(inputBuffer, inputOffset, inputLength);
		//endregion

		if(inputLength > 1)
			this.warnings.push("Boolean value encoded in more then 1 octet");

		this.isHexOnly = true;

		//region Copy input buffer to internal array
		this.valueHex = new ArrayBuffer(intBuffer.length);
		const view = new Uint8Array(this.valueHex);

		for(let i = 0; i < intBuffer.length; i++)
			view[i] = intBuffer[i];
		//endregion
		
		if(utilDecodeTC.call(this) !== 0 )
			this.value = true;
		else
			this.value = false;

		this.blockLength = inputLength;

		return (inputOffset + inputLength);
	}
	//**********************************************************************************
	//noinspection JSUnusedLocalSymbols
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		return this.valueHex;
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "BooleanValueBlock";
	}
	//**********************************************************************************
	/**
	 * Convertion for the block to JSON object
	 * @returns {{blockName, blockLength, error, warnings, valueBeforeDecode}|{blockName: string, blockLength: number, error: string, warnings: Array.<string>, valueBeforeDecode: string}}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.value = this.value;
		object.isHexOnly = this.isHexOnly;
		object.valueHex = bufferToHexCodes(this.valueHex, 0, this.valueHex.byteLength);

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
class Boolean extends BaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "Boolean" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters, LocalBooleanValueBlock);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 1; // Boolean
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "Boolean";
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of ASN.1 Sequence and Set type classes
//**************************************************************************************
class Sequence extends Constructed
{
	//**********************************************************************************
	/**
	 * Constructor for "Sequence" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 16; // Sequence
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "Sequence";
	}
	//**********************************************************************************
}
//**************************************************************************************
class Set extends Constructed
{
	//**********************************************************************************
	/**
	 * Constructor for "Set" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 17; // Set
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "Set";
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of ASN.1 Null type class
//**************************************************************************************
class Null extends BaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "Null" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters, LocalBaseBlock); // We will not have a call to "Null value block" because of specified "fromBER" and "toBER" functions

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 5; // Null
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "Null";
	}
	//**********************************************************************************
	//noinspection JSUnusedLocalSymbols
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		if(this.lenBlock.length > 0)
			this.warnings.push("Non-zero length of value block for Null type");

		if(this.idBlock.error.length === 0)
			this.blockLength += this.idBlock.blockLength;

		if(this.lenBlock.error.length === 0)
			this.blockLength += this.lenBlock.blockLength;
		
		this.blockLength += inputLength;
		
		if((inputOffset + inputLength) > inputBuffer.byteLength)
		{
			this.error = "End of input reached before message was fully decoded (inconsistent offset and length values)";
			return (-1);
		}
		
		return (inputOffset + inputLength);
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		const retBuf = new ArrayBuffer(2);

		if(sizeOnly === true)
			return retBuf;

		const retView = new Uint8Array(retBuf);
		retView[0] = 0x05;
		retView[1] = 0x00;

		return retBuf;
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of ASN.1 OctetString type class
//**************************************************************************************
class LocalOctetStringValueBlock extends LocalHexBlock(LocalConstructedValueBlock)
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalOctetStringValueBlock" class
	 * @param {Object} [parameters={}]
	 * @property {ArrayBuffer} [valueHex]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.isConstructed = getParametersValue(parameters, "isConstructed", false);
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		let resultOffset = 0;

		if(this.isConstructed === true)
		{
			this.isHexOnly = false;

			resultOffset = LocalConstructedValueBlock.prototype.fromBER.call(this, inputBuffer, inputOffset, inputLength);
			if(resultOffset === (-1))
				return resultOffset;

			for(let i = 0; i < this.value.length; i++)
			{
				const currentBlockName = this.value[i].constructor.blockName();

				if(currentBlockName === EndOfContent.blockName())
				{
					if(this.isIndefiniteForm === true)
						break;
					else
					{
						this.error = "EndOfContent is unexpected, OCTET STRING may consists of OCTET STRINGs only";
						return (-1);
					}
				}

				if(currentBlockName !== OctetString.blockName())
				{
					this.error = "OCTET STRING may consists of OCTET STRINGs only";
					return (-1);
				}
			}
		}
		else
		{
			this.isHexOnly = true;

			resultOffset = super.fromBER(inputBuffer, inputOffset, inputLength);
			this.blockLength = inputLength;
		}

		return resultOffset;
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		if(this.isConstructed === true)
			return LocalConstructedValueBlock.prototype.toBER.call(this, sizeOnly);

		let retBuf = new ArrayBuffer(this.valueHex.byteLength);

		if(sizeOnly === true)
			return retBuf;

		if(this.valueHex.byteLength === 0)
			return retBuf;

		retBuf = this.valueHex.slice(0);

		return retBuf;
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "OctetStringValueBlock";
	}
	//**********************************************************************************
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.isConstructed = this.isConstructed;
		object.isHexOnly = this.isHexOnly;
		object.valueHex = bufferToHexCodes(this.valueHex, 0, this.valueHex.byteLength);

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
class OctetString extends BaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "OctetString" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters, LocalOctetStringValueBlock);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 4; // OctetString
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		this.valueBlock.isConstructed = this.idBlock.isConstructed;
		this.valueBlock.isIndefiniteForm = this.lenBlock.isIndefiniteForm;

		//region Ability to encode empty OCTET STRING
		if(inputLength === 0)
		{
			if(this.idBlock.error.length === 0)
				this.blockLength += this.idBlock.blockLength;

			if(this.lenBlock.error.length === 0)
				this.blockLength += this.lenBlock.blockLength;

			return inputOffset;
		}
		//endregion

		return super.fromBER(inputBuffer, inputOffset, inputLength);
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "OctetString";
	}
	//**********************************************************************************
	//noinspection JSUnusedGlobalSymbols
	/**
	 * Checking that two OCTETSTRINGs are equal
	 * @param {OctetString} octetString
	 */
	isEqual(octetString)
	{
		//region Check input type
		if((octetString instanceof OctetString) === false)
			return false;
		//endregion

		//region Compare two JSON strings
		if(JSON.stringify(this) !== JSON.stringify(octetString))
			return false;
		//endregion

		return true;
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of ASN.1 BitString type class
//**************************************************************************************
class LocalBitStringValueBlock extends LocalHexBlock(LocalConstructedValueBlock)
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalBitStringValueBlock" class
	 * @param {Object} [parameters={}]
	 * @property {ArrayBuffer} [valueHex]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.unusedBits = getParametersValue(parameters, "unusedBits", 0);
		this.isConstructed = getParametersValue(parameters, "isConstructed", false);
		this.blockLength = this.valueHex.byteLength;
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		//region Ability to decode zero-length BitString value
		if(inputLength === 0)
			return inputOffset;
		//endregion

		let resultOffset = (-1);

		//region If the BISTRING supposed to be a constructed value
		if(this.isConstructed === true)
		{
			resultOffset = LocalConstructedValueBlock.prototype.fromBER.call(this, inputBuffer, inputOffset, inputLength);
			if(resultOffset === (-1))
				return resultOffset;

			for(let i = 0; i < this.value.length; i++)
			{
				const currentBlockName = this.value[i].constructor.blockName();

				if(currentBlockName === EndOfContent.blockName())
				{
					if(this.isIndefiniteForm === true)
						break;
					else
					{
						this.error = "EndOfContent is unexpected, BIT STRING may consists of BIT STRINGs only";
						return (-1);
					}
				}

				if(currentBlockName !== BitString.blockName())
				{
					this.error = "BIT STRING may consists of BIT STRINGs only";
					return (-1);
				}

				if((this.unusedBits > 0) && (this.value[i].valueBlock.unusedBits > 0))
				{
					this.error = "Usign of \"unused bits\" inside constructive BIT STRING allowed for least one only";
					return (-1);
				}

				this.unusedBits = this.value[i].valueBlock.unusedBits;
				if(this.unusedBits > 7)
				{
					this.error = "Unused bits for BitString must be in range 0-7";
					return (-1);
				}
			}

			return resultOffset;
		}
		//endregion
		//region If the BitString supposed to be a primitive value
		//region Basic check for parameters
		//noinspection JSCheckFunctionSignatures
		if(checkBufferParams(this, inputBuffer, inputOffset, inputLength) === false)
			return (-1);
		//endregion

		const intBuffer = new Uint8Array(inputBuffer, inputOffset, inputLength);

		this.unusedBits = intBuffer[0];
		
		if(this.unusedBits > 7)
		{
			this.error = "Unused bits for BitString must be in range 0-7";
			return (-1);
		}

		//region Copy input buffer to internal buffer
		this.valueHex = new ArrayBuffer(intBuffer.length - 1);
		const view = new Uint8Array(this.valueHex);
		for(let i = 0; i < (inputLength - 1); i++)
			view[i] = intBuffer[i + 1];
		//endregion

		this.blockLength = intBuffer.length;

		return (inputOffset + inputLength);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		if(this.isConstructed === true)
			return LocalConstructedValueBlock.prototype.toBER.call(this, sizeOnly);

		if(sizeOnly === true)
			return (new ArrayBuffer(this.valueHex.byteLength + 1));

		if(this.valueHex.byteLength === 0)
			return (new ArrayBuffer(0));

		const curView = new Uint8Array(this.valueHex);

		const retBuf = new ArrayBuffer(this.valueHex.byteLength + 1);
		const retView = new Uint8Array(retBuf);

		retView[0] = this.unusedBits;

		for(let i = 0; i < this.valueHex.byteLength; i++)
			retView[i + 1] = curView[i];

		return retBuf;
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "BitStringValueBlock";
	}
	//**********************************************************************************
	/**
	 * Convertion for the block to JSON object
	 * @returns {{blockName, blockLength, error, warnings, valueBeforeDecode}|{blockName: string, blockLength: number, error: string, warnings: Array.<string>, valueBeforeDecode: string}}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.unusedBits = this.unusedBits;
		object.isConstructed = this.isConstructed;
		object.isHexOnly = this.isHexOnly;
		object.valueHex = bufferToHexCodes(this.valueHex, 0, this.valueHex.byteLength);

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
class BitString extends BaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "BitString" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters, LocalBitStringValueBlock);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 3; // BitString
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "BitString";
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		//region Ability to encode empty BitString
		if(inputLength === 0)
			return inputOffset;
		//endregion

		this.valueBlock.isConstructed = this.idBlock.isConstructed;
		this.valueBlock.isIndefiniteForm = this.lenBlock.isIndefiniteForm;

		return super.fromBER(inputBuffer, inputOffset, inputLength);
	}
	//**********************************************************************************
	/**
	 * Checking that two BITSTRINGs are equal
	 * @param {BitString} bitString
	 */
	isEqual(bitString)
	{
		//region Check input type
		if((bitString instanceof BitString) === false)
			return false;
		//endregion

		//region Compare two JSON strings
		if(JSON.stringify(this) !== JSON.stringify(bitString))
			return false;
		//endregion

		return true;
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of ASN.1 Integer type class
//**************************************************************************************
/**
 * @extends LocalValueBlock
 */
class LocalIntegerValueBlock extends LocalHexBlock(LocalValueBlock)
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalIntegerValueBlock" class
	 * @param {Object} [parameters={}]
	 * @property {ArrayBuffer} [valueHex]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		if("value" in parameters)
			this.valueDec = parameters.value;
	}
	//**********************************************************************************
	/**
	 * Setter for "valueHex"
	 * @param {ArrayBuffer} _value
	 */
	set valueHex(_value)
	{
		this._valueHex = _value.slice(0);

		if(_value.byteLength >= 4)
		{
			this.warnings.push("Too big Integer for decoding, hex only");
			this.isHexOnly = true;
			this._valueDec = 0;
		}
		else
		{
			this.isHexOnly = false;

			if(_value.byteLength > 0)
				this._valueDec = utilDecodeTC.call(this);
		}
	}
	//**********************************************************************************
	/**
	 * Getter for "valueHex"
	 * @returns {ArrayBuffer}
	 */
	get valueHex()
	{
		return this._valueHex;
	}
	//**********************************************************************************
	/**
	 * Getter for "valueDec"
	 * @param {number} _value
	 */
	set valueDec(_value)
	{
		this._valueDec = _value;

		this.isHexOnly = false;
		this._valueHex = utilEncodeTC(_value);
	}
	//**********************************************************************************
	/**
	 * Getter for "valueDec"
	 * @returns {number}
	 */
	get valueDec()
	{
		return this._valueDec;
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from DER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 DER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 DER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @param {number} [expectedLength=0] Expected length of converted "valueHex" buffer
	 * @returns {number} Offset after least decoded byte
	 */
	fromDER(inputBuffer, inputOffset, inputLength, expectedLength = 0)
	{
		const offset = this.fromBER(inputBuffer, inputOffset, inputLength);
		if(offset === (-1))
			return offset;

		const view = new Uint8Array(this._valueHex);

		if((view[0] === 0x00) && ((view[1] & 0x80) !== 0))
		{
			const updatedValueHex = new ArrayBuffer(this._valueHex.byteLength - 1);
			const updatedView = new Uint8Array(updatedValueHex);

			updatedView.set(new Uint8Array(this._valueHex, 1, this._valueHex.byteLength - 1));

			this._valueHex = updatedValueHex.slice(0);
		}
		else
		{
			if(expectedLength !== 0)
			{
				if(this._valueHex.byteLength < expectedLength)
				{
					if((expectedLength - this._valueHex.byteLength) > 1)
						expectedLength = this._valueHex.byteLength + 1;
					
					const updatedValueHex = new ArrayBuffer(expectedLength);
					const updatedView = new Uint8Array(updatedValueHex);

					updatedView.set(view, expectedLength - this._valueHex.byteLength);

					this._valueHex = updatedValueHex.slice(0);
				}
			}
		}

		return offset;
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (DER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toDER(sizeOnly = false)
	{
		const view = new Uint8Array(this._valueHex);

		switch(true)
		{
			case ((view[0] & 0x80) !== 0):
				{
					const updatedValueHex = new ArrayBuffer(this._valueHex.byteLength + 1);
					const updatedView = new Uint8Array(updatedValueHex);

					updatedView[0] = 0x00;
					updatedView.set(view, 1);

					this._valueHex = updatedValueHex.slice(0);
				}
				break;
			case ((view[0] === 0x00) && ((view[1] & 0x80) === 0)):
				{
					const updatedValueHex = new ArrayBuffer(this._valueHex.byteLength - 1);
					const updatedView = new Uint8Array(updatedValueHex);

					updatedView.set(new Uint8Array(this._valueHex, 1, this._valueHex.byteLength - 1));

					this._valueHex = updatedValueHex.slice(0);
				}
				break;
			default:
		}

		return this.toBER(sizeOnly);
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		const resultOffset = super.fromBER(inputBuffer, inputOffset, inputLength);
		if(resultOffset === (-1))
			return resultOffset;

		this.blockLength = inputLength;

		return (inputOffset + inputLength);
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		//noinspection JSCheckFunctionSignatures
		return this.valueHex.slice(0);
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "IntegerValueBlock";
	}
	//**********************************************************************************
	//noinspection JSUnusedGlobalSymbols
	/**
	 * Convertion for the block to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.valueDec = this.valueDec;

		return object;
	}
	//**********************************************************************************
	/**
	 * Convert current value to decimal string representation
	 */
	toString()
	{
		//region Aux functions
		function viewAdd(first, second)
		{
			//region Initial variables
			const c = new Uint8Array([0]);
			
			let firstView = new Uint8Array(first);
			let secondView = new Uint8Array(second);
			
			let firstViewCopy = firstView.slice(0);
			const firstViewCopyLength = firstViewCopy.length - 1;
			let secondViewCopy = secondView.slice(0);
			const secondViewCopyLength = secondViewCopy.length - 1;
			
			let value = 0;
			
			const max = (secondViewCopyLength < firstViewCopyLength) ? firstViewCopyLength : secondViewCopyLength;
			
			let counter = 0;
			//endregion
			
			for(let i = max; i >= 0; i--, counter++)
			{
				switch(true)
				{
					case (counter < secondViewCopy.length):
						value = firstViewCopy[firstViewCopyLength - counter] + secondViewCopy[secondViewCopyLength - counter] + c[0];
						break;
					default:
						value = firstViewCopy[firstViewCopyLength - counter] + c[0];
				}
				
				c[0] = value / 10;
				
				switch(true)
				{
					case (counter >= firstViewCopy.length):
						firstViewCopy = utilConcatView(new Uint8Array([value % 10]), firstViewCopy);
						break;
					default:
						firstViewCopy[firstViewCopyLength - counter] = value % 10;
				}
			}
			
			if(c[0] > 0)
				firstViewCopy = utilConcatView(c, firstViewCopy);
			
			return firstViewCopy.slice(0);
		}
		
		function power2(n)
		{
			if(n >= powers2.length)
			{
				for(let p = powers2.length; p <= n; p++)
				{
					const c = new Uint8Array([0]);
					let digits = (powers2[p - 1]).slice(0);
					
					for(let i = (digits.length - 1); i >=0; i--)
					{
						const newValue = new Uint8Array([(digits[i] << 1) + c[0]]);
						c[0] = newValue[0] / 10;
						digits[i] = newValue[0] % 10;
					}
					
					if (c[0] > 0)
						digits = utilConcatView(c, digits);
					
					powers2.push(digits);
				}
			}
			
			return powers2[n];
		}
		
		function viewSub(first, second)
		{
			//region Initial variables
			let b = 0;
			
			let firstView = new Uint8Array(first);
			let secondView = new Uint8Array(second);
			
			let firstViewCopy = firstView.slice(0);
			const firstViewCopyLength = firstViewCopy.length - 1;
			let secondViewCopy = secondView.slice(0);
			const secondViewCopyLength = secondViewCopy.length - 1;
			
			let value;
			
			let counter = 0;
			//endregion
			
			for(let i = secondViewCopyLength; i >= 0; i--, counter++)
			{
				value = firstViewCopy[firstViewCopyLength - counter] - secondViewCopy[secondViewCopyLength - counter] - b;
				
				switch(true)
				{
					case (value < 0):
						b = 1;
						firstViewCopy[firstViewCopyLength - counter] = value + 10;
						break;
					default:
						b = 0;
						firstViewCopy[firstViewCopyLength - counter] = value;
				}
			}
			
			if(b > 0)
			{
				for(let i = (firstViewCopyLength - secondViewCopyLength + 1); i >= 0; i--, counter++)
				{
					value = firstViewCopy[firstViewCopyLength - counter] - b;
					
					if(value < 0)
					{
						b = 1;
						firstViewCopy[firstViewCopyLength - counter] = value + 10;
					}
					else
					{
						b = 0;
						firstViewCopy[firstViewCopyLength - counter] = value;
						break;
					}
				}
			}
			
			return firstViewCopy.slice();
		}
		//endregion
		
		//region Initial variables
		const firstBit = (this._valueHex.byteLength * 8) - 1;
		
		let digits = new Uint8Array((this._valueHex.byteLength * 8) / 3);
		let bitNumber = 0;
		let currentByte;
		
		const asn1View = new Uint8Array(this._valueHex);
		
		let result = "";
		
		let flag = false;
		//endregion
		
		//region Calculate number
		for(let byteNumber = (this._valueHex.byteLength - 1); byteNumber >= 0; byteNumber--)
		{
			currentByte = asn1View[byteNumber];
			
			for(let i = 0; i < 8; i++)
			{
				if((currentByte & 1) === 1)
				{
					switch(bitNumber)
					{
						case firstBit:
							digits = viewSub(power2(bitNumber), digits);
							result = "-";
							break;
						default:
							digits = viewAdd(digits, power2(bitNumber));
					}
				}
				
				bitNumber++;
				currentByte >>= 1;
			}
		}
		//endregion
		
		//region Print number
		for(let i = 0; i < digits.length; i++)
		{
			if(digits[i])
				flag = true;
			
			if(flag)
				result += digitsString.charAt(digits[i]);
		}
		
		if(flag === false)
			result += digitsString.charAt(0);
		//endregion
		
		return result;
	}
	//**********************************************************************************
}
//**************************************************************************************
class Integer extends BaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "Integer" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters, LocalIntegerValueBlock);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 2; // Integer
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "Integer";
	}
	//**********************************************************************************
	//noinspection JSUnusedGlobalSymbols
	/**
	 * Compare two Integer object, or Integer and ArrayBuffer objects
	 * @param {!Integer|ArrayBuffer} otherValue
	 * @returns {boolean}
	 */
	isEqual(otherValue)
	{
		if(otherValue instanceof Integer)
		{
			if(this.valueBlock.isHexOnly && otherValue.valueBlock.isHexOnly) // Compare two ArrayBuffers
				return isEqualBuffer(this.valueBlock.valueHex, otherValue.valueBlock.valueHex);

			if(this.valueBlock.isHexOnly === otherValue.valueBlock.isHexOnly)
				return (this.valueBlock.valueDec === otherValue.valueBlock.valueDec);

			return false;
		}
		
		if(otherValue instanceof ArrayBuffer)
			return isEqualBuffer(this.valueBlock.valueHex, otherValue);

		return false;
	}
	//**********************************************************************************
	/**
	 * Convert current Integer value from BER into DER format
	 * @returns {Integer}
	 */
	convertToDER()
	{
		const integer = new Integer({ valueHex: this.valueBlock.valueHex });
		integer.valueBlock.toDER();

		return integer;
	}
	//**********************************************************************************
	/**
	 * Convert current Integer value from DER to BER format
	 * @returns {Integer}
	 */
	convertFromDER()
	{
		const expectedLength = (this.valueBlock.valueHex.byteLength % 2) ? (this.valueBlock.valueHex.byteLength + 1) : this.valueBlock.valueHex.byteLength;
		const integer = new Integer({ valueHex: this.valueBlock.valueHex });
		integer.valueBlock.fromDER(integer.valueBlock.valueHex, 0, integer.valueBlock.valueHex.byteLength, expectedLength);
		
		return integer;
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of ASN.1 Enumerated type class
//**************************************************************************************
class Enumerated extends Integer
{
	//**********************************************************************************
	/**
	 * Constructor for "Enumerated" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 10; // Enumerated
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "Enumerated";
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of ASN.1 ObjectIdentifier type class
//**************************************************************************************
class LocalSidValueBlock extends LocalHexBlock(LocalBaseBlock)
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalSidValueBlock" class
	 * @param {Object} [parameters={}]
	 * @property {number} [valueDec]
	 * @property {boolean} [isFirstSid]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.valueDec = getParametersValue(parameters, "valueDec", -1);
		this.isFirstSid = getParametersValue(parameters, "isFirstSid", false);
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "sidBlock";
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		if(inputLength === 0)
			return inputOffset;

		//region Basic check for parameters
		//noinspection JSCheckFunctionSignatures
		if(checkBufferParams(this, inputBuffer, inputOffset, inputLength) === false)
			return (-1);
		//endregion

		const intBuffer = new Uint8Array(inputBuffer, inputOffset, inputLength);

		this.valueHex = new ArrayBuffer(inputLength);
		let view = new Uint8Array(this.valueHex);

		for(let i = 0; i < inputLength; i++)
		{
			view[i] = intBuffer[i] & 0x7F;

			this.blockLength++;

			if((intBuffer[i] & 0x80) === 0x00)
				break;
		}

		//region Ajust size of valueHex buffer
		const tempValueHex = new ArrayBuffer(this.blockLength);
		const tempView = new Uint8Array(tempValueHex);

		for(let i = 0; i < this.blockLength; i++)
			tempView[i] = view[i];

		//noinspection JSCheckFunctionSignatures
		this.valueHex = tempValueHex.slice(0);
		view = new Uint8Array(this.valueHex);
		//endregion

		if((intBuffer[this.blockLength - 1] & 0x80) !== 0x00)
		{
			this.error = "End of input reached before message was fully decoded";
			return (-1);
		}

		if(view[0] === 0x00)
			this.warnings.push("Needlessly long format of SID encoding");

		if(this.blockLength <= 8)
			this.valueDec = utilFromBase(view, 7);
		else
		{
			this.isHexOnly = true;
			this.warnings.push("Too big SID for decoding, hex only");
		}

		return (inputOffset + this.blockLength);
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		//region Initial variables
		let retBuf;
		let retView;
		//endregion

		if(this.isHexOnly)
		{
			if(sizeOnly === true)
				return (new ArrayBuffer(this.valueHex.byteLength));

			const curView = new Uint8Array(this.valueHex);

			retBuf = new ArrayBuffer(this.blockLength);
			retView = new Uint8Array(retBuf);

			for(let i = 0; i < (this.blockLength - 1); i++)
				retView[i] = curView[i] | 0x80;

			retView[this.blockLength - 1] = curView[this.blockLength - 1];

			return retBuf;
		}

		const encodedBuf = utilToBase(this.valueDec, 7);
		if(encodedBuf.byteLength === 0)
		{
			this.error = "Error during encoding SID value";
			return (new ArrayBuffer(0));
		}

		retBuf = new ArrayBuffer(encodedBuf.byteLength);

		if(sizeOnly === false)
		{
			const encodedView = new Uint8Array(encodedBuf);
			retView = new Uint8Array(retBuf);

			for(let i = 0; i < (encodedBuf.byteLength - 1); i++)
				retView[i] = encodedView[i] | 0x80;

			retView[encodedBuf.byteLength - 1] = encodedView[encodedBuf.byteLength - 1];
		}

		return retBuf;
	}
	//**********************************************************************************
	/**
	 * Create string representation of current SID block
	 * @returns {string}
	 */
	toString()
	{
		let result = "";

		if(this.isHexOnly === true)
			result = bufferToHexCodes(this.valueHex, 0, this.valueHex.byteLength);
		else
		{
			if(this.isFirstSid)
			{
				let sidValue = this.valueDec;

				if(this.valueDec <= 39)
					result = "0.";
				else
				{
					if(this.valueDec <= 79)
					{
						result = "1.";
						sidValue -= 40;
					}
					else
					{
						result = "2.";
						sidValue -= 80;
					}
				}

				result = result + sidValue.toString();
			}
			else
				result = this.valueDec.toString();
		}

		return result;
	}
	//**********************************************************************************
	//noinspection JSUnusedGlobalSymbols
	/**
	 * Convertion for the block to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.valueDec = this.valueDec;
		object.isFirstSid = this.isFirstSid;

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
class LocalObjectIdentifierValueBlock extends LocalValueBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalObjectIdentifierValueBlock" class
	 * @param {Object} [parameters={}]
	 * @property {ArrayBuffer} [valueHex]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.fromString(getParametersValue(parameters, "value", ""));
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		let resultOffset = inputOffset;

		while(inputLength > 0)
		{
			const sidBlock = new LocalSidValueBlock();
			resultOffset = sidBlock.fromBER(inputBuffer, resultOffset, inputLength);
			if(resultOffset === (-1))
			{
				this.blockLength = 0;
				this.error = sidBlock.error;
				return resultOffset;
			}

			if(this.value.length === 0)
				sidBlock.isFirstSid = true;

			this.blockLength += sidBlock.blockLength;
			inputLength -= sidBlock.blockLength;

			this.value.push(sidBlock);
		}

		return resultOffset;
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		let retBuf = new ArrayBuffer(0);

		for(let i = 0; i < this.value.length; i++)
		{
			const valueBuf = this.value[i].toBER(sizeOnly);
			if(valueBuf.byteLength === 0)
			{
				this.error = this.value[i].error;
				return (new ArrayBuffer(0));
			}

			retBuf = utilConcatBuf(retBuf, valueBuf);
		}

		return retBuf;
	}
	//**********************************************************************************
	/**
	 * Create "LocalObjectIdentifierValueBlock" class from string
	 * @param {string} string Input string to convert from
	 * @returns {boolean}
	 */
	fromString(string)
	{
		this.value = []; // Clear existing SID values

		let pos1 = 0;
		let pos2 = 0;

		let sid = "";

		let flag = false;

		do
		{
			pos2 = string.indexOf(".", pos1);
			if(pos2 === (-1))
				sid = string.substr(pos1);
			else
				sid = string.substr(pos1, pos2 - pos1);

			pos1 = pos2 + 1;

			if(flag)
			{
				const sidBlock = this.value[0];

				let plus = 0;

				switch(sidBlock.valueDec)
				{
					case 0:
						break;
					case 1:
						plus = 40;
						break;
					case 2:
						plus = 80;
						break;
					default:
						this.value = []; // clear SID array
						return false; // ???
				}

				const parsedSID = parseInt(sid, 10);
				if(isNaN(parsedSID))
					return true;

				sidBlock.valueDec = parsedSID + plus;

				flag = false;
			}
			else
			{
				const sidBlock = new LocalSidValueBlock();
				sidBlock.valueDec = parseInt(sid, 10);
				if(isNaN(sidBlock.valueDec))
					return true;

				if(this.value.length === 0)
				{
					sidBlock.isFirstSid = true;
					flag = true;
				}

				this.value.push(sidBlock);
			}
		} while(pos2 !== (-1));

		return true;
	}
	//**********************************************************************************
	/**
	 * Converts "LocalObjectIdentifierValueBlock" class to string
	 * @returns {string}
	 */
	toString()
	{
		let result = "";
		let isHexOnly = false;

		for(let i = 0; i < this.value.length; i++)
		{
			isHexOnly = this.value[i].isHexOnly;

			let sidStr = this.value[i].toString();

			if(i !== 0)
				result = `${result}.`;

			if(isHexOnly)
			{
				sidStr = `{${sidStr}}`;

				if(this.value[i].isFirstSid)
					result = `2.{${sidStr} - 80}`;
				else
					result = result + sidStr;
			}
			else
				result = result + sidStr;
		}

		return result;
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "ObjectIdentifierValueBlock";
	}
	//**********************************************************************************
	/**
	 * Convertion for the block to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.value = this.toString();
		object.sidArray = [];
		for(let i = 0; i < this.value.length; i++)
			object.sidArray.push(this.value[i].toJSON());

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends BaseBlock
 */
class ObjectIdentifier extends BaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "ObjectIdentifier" class
	 * @param {Object} [parameters={}]
	 * @property {ArrayBuffer} [valueHex]
	 */
	constructor(parameters = {})
	{
		super(parameters, LocalObjectIdentifierValueBlock);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 6; // OBJECT IDENTIFIER
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "ObjectIdentifier";
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of all string's classes
//**************************************************************************************
class LocalUtf8StringValueBlock extends LocalHexBlock(LocalBaseBlock)
{
	//**********************************************************************************
	//noinspection JSUnusedGlobalSymbols
	/**
	 * Constructor for "LocalUtf8StringValueBlock" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.isHexOnly = true;
		this.value = ""; // String representation of decoded ArrayBuffer
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "Utf8StringValueBlock";
	}
	//**********************************************************************************
	//noinspection JSUnusedGlobalSymbols
	/**
	 * Convertion for the block to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.value = this.value;

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends BaseBlock
 */
class Utf8String extends BaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "Utf8String" class
	 * @param {Object} [parameters={}]
	 * @property {ArrayBuffer} [valueHex]
	 */
	constructor(parameters = {})
	{
		super(parameters, LocalUtf8StringValueBlock);

		if("value" in parameters)
			this.fromString(parameters.value);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 12; // Utf8String
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "Utf8String";
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		const resultOffset = this.valueBlock.fromBER(inputBuffer, inputOffset, (this.lenBlock.isIndefiniteForm === true) ? inputLength : this.lenBlock.length);
		if(resultOffset === (-1))
		{
			this.error = this.valueBlock.error;
			return resultOffset;
		}

		this.fromBuffer(this.valueBlock.valueHex);

		if(this.idBlock.error.length === 0)
			this.blockLength += this.idBlock.blockLength;

		if(this.lenBlock.error.length === 0)
			this.blockLength += this.lenBlock.blockLength;

		if(this.valueBlock.error.length === 0)
			this.blockLength += this.valueBlock.blockLength;

		return resultOffset;
	}
	//**********************************************************************************
	/**
	 * Function converting ArrayBuffer into ASN.1 internal string
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 */
	fromBuffer(inputBuffer)
	{
		this.valueBlock.value = String.fromCharCode.apply(null, new Uint8Array(inputBuffer));

		try
		{
			//noinspection JSDeprecatedSymbols
			this.valueBlock.value = decodeURIComponent(escape(this.valueBlock.value));
		}
		catch(ex)
		{
			this.warnings.push(`Error during \"decodeURIComponent\": ${ex}, using raw string`);
		}
	}
	//**********************************************************************************
	/**
	 * Function converting JavaScript string into ASN.1 internal class
	 * @param {!string} inputString ASN.1 BER encoded array
	 */
	fromString(inputString)
	{
		//noinspection JSDeprecatedSymbols
		const str = unescape(encodeURIComponent(inputString));
		const strLen = str.length;

		this.valueBlock.valueHex = new ArrayBuffer(strLen);
		const view = new Uint8Array(this.valueBlock.valueHex);

		for(let i = 0; i < strLen; i++)
			view[i] = str.charCodeAt(i);

		this.valueBlock.value = inputString;
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends LocalBaseBlock
 * @extends LocalHexBlock
 */
class LocalBmpStringValueBlock extends LocalHexBlock(LocalBaseBlock)
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalBmpStringValueBlock" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.isHexOnly = true;
		this.value = "";
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "BmpStringValueBlock";
	}
	//**********************************************************************************
	//noinspection JSUnusedGlobalSymbols
	/**
	 * Convertion for the block to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.value = this.value;

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends BaseBlock
 */
class BmpString extends BaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "BmpString" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters, LocalBmpStringValueBlock);

		if("value" in parameters)
			this.fromString(parameters.value);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 30; // BmpString
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "BmpString";
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		const resultOffset = this.valueBlock.fromBER(inputBuffer, inputOffset, (this.lenBlock.isIndefiniteForm === true) ? inputLength : this.lenBlock.length);
		if(resultOffset === (-1))
		{
			this.error = this.valueBlock.error;
			return resultOffset;
		}

		this.fromBuffer(this.valueBlock.valueHex);

		if(this.idBlock.error.length === 0)
			this.blockLength += this.idBlock.blockLength;

		if(this.lenBlock.error.length === 0)
			this.blockLength += this.lenBlock.blockLength;

		if(this.valueBlock.error.length === 0)
			this.blockLength += this.valueBlock.blockLength;

		return resultOffset;
	}
	//**********************************************************************************
	/**
	 * Function converting ArrayBuffer into ASN.1 internal string
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 */
	fromBuffer(inputBuffer)
	{
		//noinspection JSCheckFunctionSignatures
		const copyBuffer = inputBuffer.slice(0);
		const valueView = new Uint8Array(copyBuffer);

		for(let i = 0; i < valueView.length; i = i + 2)
		{
			const temp = valueView[i];

			valueView[i] = valueView[i + 1];
			valueView[i + 1] = temp;
		}

		this.valueBlock.value = String.fromCharCode.apply(null, new Uint16Array(copyBuffer));
	}
	//**********************************************************************************
	/**
	 * Function converting JavaScript string into ASN.1 internal class
	 * @param {!string} inputString ASN.1 BER encoded array
	 */
	fromString(inputString)
	{
		const strLength = inputString.length;

		this.valueBlock.valueHex = new ArrayBuffer(strLength * 2);
		const valueHexView = new Uint8Array(this.valueBlock.valueHex);

		for(let i = 0; i < strLength; i++)
		{
			const codeBuf = utilToBase(inputString.charCodeAt(i), 8);
			const codeView = new Uint8Array(codeBuf);
			if(codeView.length > 2)
				continue;

			const dif = 2 - codeView.length;

			for(let j = (codeView.length - 1); j >= 0; j--)
				valueHexView[i * 2 + j + dif] = codeView[j];
		}

		this.valueBlock.value = inputString;
	}
	//**********************************************************************************
}
//**************************************************************************************
class LocalUniversalStringValueBlock extends LocalHexBlock(LocalBaseBlock)
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalUniversalStringValueBlock" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.isHexOnly = true;
		this.value = "";
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "UniversalStringValueBlock";
	}
	//**********************************************************************************
	//noinspection JSUnusedGlobalSymbols
	/**
	 * Convertion for the block to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.value = this.value;

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends BaseBlock
 */
class UniversalString extends BaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "UniversalString" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters, LocalUniversalStringValueBlock);

		if("value" in parameters)
			this.fromString(parameters.value);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 28; // UniversalString
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "UniversalString";
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		const resultOffset = this.valueBlock.fromBER(inputBuffer, inputOffset, (this.lenBlock.isIndefiniteForm === true) ? inputLength : this.lenBlock.length);
		if(resultOffset === (-1))
		{
			this.error = this.valueBlock.error;
			return resultOffset;
		}

		this.fromBuffer(this.valueBlock.valueHex);

		if(this.idBlock.error.length === 0)
			this.blockLength += this.idBlock.blockLength;

		if(this.lenBlock.error.length === 0)
			this.blockLength += this.lenBlock.blockLength;

		if(this.valueBlock.error.length === 0)
			this.blockLength += this.valueBlock.blockLength;

		return resultOffset;
	}
	//**********************************************************************************
	/**
	 * Function converting ArrayBuffer into ASN.1 internal string
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 */
	fromBuffer(inputBuffer)
	{
		//noinspection JSCheckFunctionSignatures
		const copyBuffer = inputBuffer.slice(0);
		const valueView = new Uint8Array(copyBuffer);

		for(let i = 0; i < valueView.length; i = i + 4)
		{
			valueView[i] = valueView[i + 3];
			valueView[i + 1] = valueView[i + 2];
			valueView[i + 2] = 0x00;
			valueView[i + 3] = 0x00;
		}

		this.valueBlock.value = String.fromCharCode.apply(null, new Uint32Array(copyBuffer));
	}
	//**********************************************************************************
	/**
	 * Function converting JavaScript string into ASN.1 internal class
	 * @param {!string} inputString ASN.1 BER encoded array
	 */
	fromString(inputString)
	{
		const strLength = inputString.length;

		this.valueBlock.valueHex = new ArrayBuffer(strLength * 4);
		const valueHexView = new Uint8Array(this.valueBlock.valueHex);

		for(let i = 0; i < strLength; i++)
		{
			const codeBuf = utilToBase(inputString.charCodeAt(i), 8);
			const codeView = new Uint8Array(codeBuf);
			if(codeView.length > 4)
				continue;

			const dif = 4 - codeView.length;

			for(let j = (codeView.length - 1); j >= 0; j--)
				valueHexView[i * 4 + j + dif] = codeView[j];
		}

		this.valueBlock.value = inputString;
	}
	//**********************************************************************************
}
//**************************************************************************************
class LocalSimpleStringValueBlock extends LocalHexBlock(LocalBaseBlock)
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalSimpleStringValueBlock" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.value = "";
		this.isHexOnly = true;
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "SimpleStringValueBlock";
	}
	//**********************************************************************************
	//noinspection JSUnusedGlobalSymbols
	/**
	 * Convertion for the block to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.value = this.value;

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends BaseBlock
 */
class LocalSimpleStringBlock extends BaseBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "LocalSimpleStringBlock" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters, LocalSimpleStringValueBlock);

		if("value" in parameters)
			this.fromString(parameters.value);
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "SIMPLESTRING";
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		const resultOffset = this.valueBlock.fromBER(inputBuffer, inputOffset, (this.lenBlock.isIndefiniteForm === true) ? inputLength : this.lenBlock.length);
		if(resultOffset === (-1))
		{
			this.error = this.valueBlock.error;
			return resultOffset;
		}

		this.fromBuffer(this.valueBlock.valueHex);

		if(this.idBlock.error.length === 0)
			this.blockLength += this.idBlock.blockLength;

		if(this.lenBlock.error.length === 0)
			this.blockLength += this.lenBlock.blockLength;

		if(this.valueBlock.error.length === 0)
			this.blockLength += this.valueBlock.blockLength;

		return resultOffset;
	}
	//**********************************************************************************
	/**
	 * Function converting ArrayBuffer into ASN.1 internal string
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 */
	fromBuffer(inputBuffer)
	{
		this.valueBlock.value = String.fromCharCode.apply(null, new Uint8Array(inputBuffer));
	}
	//**********************************************************************************
	/**
	 * Function converting JavaScript string into ASN.1 internal class
	 * @param {!string} inputString ASN.1 BER encoded array
	 */
	fromString(inputString)
	{
		const strLen = inputString.length;

		this.valueBlock.valueHex = new ArrayBuffer(strLen);
		const view = new Uint8Array(this.valueBlock.valueHex);

		for(let i = 0; i < strLen; i++)
			view[i] = inputString.charCodeAt(i);

		this.valueBlock.value = inputString;
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends LocalSimpleStringBlock
 */
class NumericString extends LocalSimpleStringBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "NumericString" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 18; // NumericString
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "NumericString";
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends LocalSimpleStringBlock
 */
class PrintableString extends LocalSimpleStringBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "PrintableString" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 19; // PrintableString
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "PrintableString";
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends LocalSimpleStringBlock
 */
class TeletexString extends LocalSimpleStringBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "TeletexString" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 20; // TeletexString
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "TeletexString";
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends LocalSimpleStringBlock
 */
class VideotexString extends LocalSimpleStringBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "VideotexString" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 21; // VideotexString
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "VideotexString";
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends LocalSimpleStringBlock
 */
class IA5String extends LocalSimpleStringBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "IA5String" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 22; // IA5String
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "IA5String";
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends LocalSimpleStringBlock
 */
class GraphicString extends LocalSimpleStringBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "GraphicString" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 25; // GraphicString
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "GraphicString";
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends LocalSimpleStringBlock
 */
class VisibleString extends LocalSimpleStringBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "VisibleString" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 26; // VisibleString
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "VisibleString";
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends LocalSimpleStringBlock
 */
class GeneralString extends LocalSimpleStringBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "GeneralString" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 27; // GeneralString
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "GeneralString";
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends LocalSimpleStringBlock
 */
class CharacterString extends LocalSimpleStringBlock
{
	//**********************************************************************************
	/**
	 * Constructor for "CharacterString" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 29; // CharacterString
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "CharacterString";
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of all date and time classes
//**************************************************************************************
/**
 * @extends VisibleString
 */
class UTCTime extends VisibleString
{
	//**********************************************************************************
	/**
	 * Constructor for "UTCTime" class
	 * @param {Object} [parameters={}]
	 * @property {string} [value] String representatio of the date
	 * @property {Date} [valueDate] JavaScript "Date" object
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.year = 0;
		this.month = 0;
		this.day = 0;
		this.hour = 0;
		this.minute = 0;
		this.second = 0;

		//region Create UTCTime from ASN.1 UTC string value
		if("value" in parameters)
		{
			this.fromString(parameters.value);

			this.valueBlock.valueHex = new ArrayBuffer(parameters.value.length);
			const view = new Uint8Array(this.valueBlock.valueHex);

			for(let i = 0; i < parameters.value.length; i++)
				view[i] = parameters.value.charCodeAt(i);
		}
		//endregion
		//region Create GeneralizedTime from JavaScript Date type
		if("valueDate" in parameters)
		{
			this.fromDate(parameters.valueDate);
			this.valueBlock.valueHex = this.toBuffer();
		}
		//endregion

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 23; // UTCTime
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		const resultOffset = this.valueBlock.fromBER(inputBuffer, inputOffset, (this.lenBlock.isIndefiniteForm === true) ? inputLength : this.lenBlock.length);
		if(resultOffset === (-1))
		{
			this.error = this.valueBlock.error;
			return resultOffset;
		}

		this.fromBuffer(this.valueBlock.valueHex);

		if(this.idBlock.error.length === 0)
			this.blockLength += this.idBlock.blockLength;

		if(this.lenBlock.error.length === 0)
			this.blockLength += this.lenBlock.blockLength;

		if(this.valueBlock.error.length === 0)
			this.blockLength += this.valueBlock.blockLength;

		return resultOffset;
	}
	//**********************************************************************************
	/**
	 * Function converting ArrayBuffer into ASN.1 internal string
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 */
	fromBuffer(inputBuffer)
	{
		this.fromString(String.fromCharCode.apply(null, new Uint8Array(inputBuffer)));
	}
	//**********************************************************************************
	/**
	 * Function converting ASN.1 internal string into ArrayBuffer
	 * @returns {ArrayBuffer}
	 */
	toBuffer()
	{
		const str = this.toString();

		const buffer = new ArrayBuffer(str.length);
		const view = new Uint8Array(buffer);

		for(let i = 0; i < str.length; i++)
			view[i] = str.charCodeAt(i);

		return buffer;
	}
	//**********************************************************************************
	/**
	 * Function converting "Date" object into ASN.1 internal string
	 * @param {!Date} inputDate JavaScript "Date" object
	 */
	fromDate(inputDate)
	{
		this.year = inputDate.getUTCFullYear();
		this.month = inputDate.getUTCMonth() + 1;
		this.day = inputDate.getUTCDate();
		this.hour = inputDate.getUTCHours();
		this.minute = inputDate.getUTCMinutes();
		this.second = inputDate.getUTCSeconds();
	}
	//**********************************************************************************
	//noinspection JSUnusedGlobalSymbols
	/**
	 * Function converting ASN.1 internal string into "Date" object
	 * @returns {Date}
	 */
	toDate()
	{
		return (new Date(Date.UTC(this.year, this.month - 1, this.day, this.hour, this.minute, this.second)));
	}
	//**********************************************************************************
	/**
	 * Function converting JavaScript string into ASN.1 internal class
	 * @param {!string} inputString ASN.1 BER encoded array
	 */
	fromString(inputString)
	{
		//region Parse input string
		const parser = /(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z/ig;
		const parserArray = parser.exec(inputString);
		if(parserArray === null)
		{
			this.error = "Wrong input string for convertion";
			return;
		}
		//endregion

		//region Store parsed values
		const year = parseInt(parserArray[1], 10);
		if(year >= 50)
			this.year = 1900 + year;
		else
			this.year = 2000 + year;

		this.month = parseInt(parserArray[2], 10);
		this.day = parseInt(parserArray[3], 10);
		this.hour = parseInt(parserArray[4], 10);
		this.minute = parseInt(parserArray[5], 10);
		this.second = parseInt(parserArray[6], 10);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Function converting ASN.1 internal class into JavaScript string
	 * @returns {string}
	 */
	toString()
	{
		const outputArray = new Array(7);

		outputArray[0] = padNumber(((this.year < 2000) ? (this.year - 1900) : (this.year - 2000)), 2);
		outputArray[1] = padNumber(this.month, 2);
		outputArray[2] = padNumber(this.day, 2);
		outputArray[3] = padNumber(this.hour, 2);
		outputArray[4] = padNumber(this.minute, 2);
		outputArray[5] = padNumber(this.second, 2);
		outputArray[6] = "Z";

		return outputArray.join("");
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "UTCTime";
	}
	//**********************************************************************************
	/**
	 * Convertion for the block to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.year = this.year;
		object.month = this.month;
		object.day = this.day;
		object.hour = this.hour;
		object.minute = this.minute;
		object.second = this.second;

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends VisibleString
 */
class GeneralizedTime extends VisibleString
{
	//**********************************************************************************
	/**
	 * Constructor for "GeneralizedTime" class
	 * @param {Object} [parameters={}]
	 * @property {string} [value] String representatio of the date
	 * @property {Date} [valueDate] JavaScript "Date" object
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.year = 0;
		this.month = 0;
		this.day = 0;
		this.hour = 0;
		this.minute = 0;
		this.second = 0;
		this.millisecond = 0;

		//region Create UTCTime from ASN.1 UTC string value
		if("value" in parameters)
		{
			this.fromString(parameters.value);

			this.valueBlock.valueHex = new ArrayBuffer(parameters.value.length);
			const view = new Uint8Array(this.valueBlock.valueHex);

			for(let i = 0; i < parameters.value.length; i++)
				view[i] = parameters.value.charCodeAt(i);
		}
		//endregion
		//region Create GeneralizedTime from JavaScript Date type
		if("valueDate" in parameters)
		{
			this.fromDate(parameters.valueDate);
			this.valueBlock.valueHex = this.toBuffer();
		}
		//endregion

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 24; // GeneralizedTime
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		const resultOffset = this.valueBlock.fromBER(inputBuffer, inputOffset, (this.lenBlock.isIndefiniteForm === true) ? inputLength : this.lenBlock.length);
		if(resultOffset === (-1))
		{
			this.error = this.valueBlock.error;
			return resultOffset;
		}

		this.fromBuffer(this.valueBlock.valueHex);

		if(this.idBlock.error.length === 0)
			this.blockLength += this.idBlock.blockLength;

		if(this.lenBlock.error.length === 0)
			this.blockLength += this.lenBlock.blockLength;

		if(this.valueBlock.error.length === 0)
			this.blockLength += this.valueBlock.blockLength;

		return resultOffset;
	}
	//**********************************************************************************
	/**
	 * Function converting ArrayBuffer into ASN.1 internal string
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 */
	fromBuffer(inputBuffer)
	{
		this.fromString(String.fromCharCode.apply(null, new Uint8Array(inputBuffer)));
	}
	//**********************************************************************************
	/**
	 * Function converting ASN.1 internal string into ArrayBuffer
	 * @returns {ArrayBuffer}
	 */
	toBuffer()
	{
		const str = this.toString();

		const buffer = new ArrayBuffer(str.length);
		const view = new Uint8Array(buffer);

		for(let i = 0; i < str.length; i++)
			view[i] = str.charCodeAt(i);

		return buffer;
	}
	//**********************************************************************************
	/**
	 * Function converting "Date" object into ASN.1 internal string
	 * @param {!Date} inputDate JavaScript "Date" object
	 */
	fromDate(inputDate)
	{
		this.year = inputDate.getUTCFullYear();
		this.month = inputDate.getUTCMonth() + 1;
		this.day = inputDate.getUTCDate();
		this.hour = inputDate.getUTCHours();
		this.minute = inputDate.getUTCMinutes();
		this.second = inputDate.getUTCSeconds();
		this.millisecond = inputDate.getUTCMilliseconds();
	}
	//**********************************************************************************
	//noinspection JSUnusedGlobalSymbols
	/**
	 * Function converting ASN.1 internal string into "Date" object
	 * @returns {Date}
	 */
	toDate()
	{
		return (new Date(Date.UTC(this.year, this.month - 1, this.day, this.hour, this.minute, this.second, this.millisecond)));
	}
	//**********************************************************************************
	/**
	 * Function converting JavaScript string into ASN.1 internal class
	 * @param {!string} inputString ASN.1 BER encoded array
	 */
	fromString(inputString)
	{
		//region Initial variables
		let isUTC = false;

		let timeString = "";
		let dateTimeString = "";
		let fractionPart = 0;

		let parser;

		let hourDifference = 0;
		let minuteDifference = 0;
		//endregion

		//region Convert as UTC time
		if(inputString[inputString.length - 1] === "Z")
		{
			timeString = inputString.substr(0, inputString.length - 1);

			isUTC = true;
		}
		//endregion
		//region Convert as local time
		else
		{
			//noinspection JSPrimitiveTypeWrapperUsage
			const number = new Number(inputString[inputString.length - 1]);

			if(isNaN(number.valueOf()))
				throw new Error("Wrong input string for convertion");

			timeString = inputString;
		}
		//endregion

		//region Check that we do not have a "+" and "-" symbols inside UTC time
		if(isUTC)
		{
			if(timeString.indexOf("+") !== (-1))
				throw new Error("Wrong input string for convertion");

			if(timeString.indexOf("-") !== (-1))
				throw new Error("Wrong input string for convertion");
		}
		//endregion
		//region Get "UTC time difference" in case of local time
		else
		{
			let multiplier = 1;
			let differencePosition = timeString.indexOf("+");
			let differenceString = "";

			if(differencePosition === (-1))
			{
				differencePosition = timeString.indexOf("-");
				multiplier = (-1);
			}

			if(differencePosition !== (-1))
			{
				differenceString = timeString.substr(differencePosition + 1);
				timeString = timeString.substr(0, differencePosition);

				if((differenceString.length !== 2) && (differenceString.length !== 4))
					throw new Error("Wrong input string for convertion");

				//noinspection JSPrimitiveTypeWrapperUsage
				let number = new Number(differenceString.substr(0, 2));

				if(isNaN(number.valueOf()))
					throw new Error("Wrong input string for convertion");

				hourDifference = multiplier * number;

				if(differenceString.length === 4)
				{
					//noinspection JSPrimitiveTypeWrapperUsage
					number = new Number(differenceString.substr(2, 2));

					if(isNaN(number.valueOf()))
						throw new Error("Wrong input string for convertion");

					minuteDifference = multiplier * number;
				}
			}
		}
		//endregion

		//region Get position of fraction point
		let fractionPointPosition = timeString.indexOf("."); // Check for "full stop" symbol
		if(fractionPointPosition === (-1))
			fractionPointPosition = timeString.indexOf(","); // Check for "comma" symbol
		//endregion

		//region Get fraction part
		if(fractionPointPosition !== (-1))
		{
			//noinspection JSPrimitiveTypeWrapperUsage
			const fractionPartCheck = new Number(`0${timeString.substr(fractionPointPosition)}`);

			if(isNaN(fractionPartCheck.valueOf()))
				throw new Error("Wrong input string for convertion");

			fractionPart = fractionPartCheck.valueOf();

			dateTimeString = timeString.substr(0, fractionPointPosition);
		}
		else
			dateTimeString = timeString;
		//endregion

		//region Parse internal date
		switch(true)
		{
			case (dateTimeString.length === 8): // "YYYYMMDD"
				parser = /(\d{4})(\d{2})(\d{2})/ig;
				if(fractionPointPosition !== (-1))
					throw new Error("Wrong input string for convertion"); // Here we should not have a "fraction point"
				break;
			case (dateTimeString.length === 10): // "YYYYMMDDHH"
				parser = /(\d{4})(\d{2})(\d{2})(\d{2})/ig;

				if(fractionPointPosition !== (-1))
				{
					let fractionResult = 60 * fractionPart;
					this.minute = Math.floor(fractionResult);

					fractionResult = 60 * (fractionResult - this.minute);
					this.second = Math.floor(fractionResult);

					fractionResult = 1000 * (fractionResult - this.second);
					this.millisecond = Math.floor(fractionResult);
				}
				break;
			case (dateTimeString.length === 12): // "YYYYMMDDHHMM"
				parser = /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})/ig;

				if(fractionPointPosition !== (-1))
				{
					let fractionResult = 60 * fractionPart;
					this.second = Math.floor(fractionResult);

					fractionResult = 1000 * (fractionResult - this.second);
					this.millisecond = Math.floor(fractionResult);
				}
				break;
			case (dateTimeString.length === 14): // "YYYYMMDDHHMMSS"
				parser = /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/ig;

				if(fractionPointPosition !== (-1))
				{
					const fractionResult = 1000 * fractionPart;
					this.millisecond = Math.floor(fractionResult);
				}
				break;
			default:
				throw new Error("Wrong input string for convertion");
		}
		//endregion

		//region Put parsed values at right places
		const parserArray = parser.exec(dateTimeString);
		if(parserArray === null)
			throw new Error("Wrong input string for convertion");

		for(let j = 1; j < parserArray.length; j++)
		{
			switch(j)
			{
				case 1:
					this.year = parseInt(parserArray[j], 10);
					break;
				case 2:
					this.month = parseInt(parserArray[j], 10);
					break;
				case 3:
					this.day = parseInt(parserArray[j], 10);
					break;
				case 4:
					this.hour = parseInt(parserArray[j], 10) + hourDifference;
					break;
				case 5:
					this.minute = parseInt(parserArray[j], 10) + minuteDifference;
					break;
				case 6:
					this.second = parseInt(parserArray[j], 10);
					break;
				default:
					throw new Error("Wrong input string for convertion");
			}
		}
		//endregion

		//region Get final date
		if(isUTC === false)
		{
			const tempDate = new Date(this.year, this.month, this.day, this.hour, this.minute, this.second, this.millisecond);

			this.year = tempDate.getUTCFullYear();
			this.month = tempDate.getUTCMonth();
			this.day = tempDate.getUTCDay();
			this.hour = tempDate.getUTCHours();
			this.minute = tempDate.getUTCMinutes();
			this.second = tempDate.getUTCSeconds();
			this.millisecond = tempDate.getUTCMilliseconds();
		}
		//endregion
	}
	//**********************************************************************************
	/**
	 * Function converting ASN.1 internal class into JavaScript string
	 * @returns {string}
	 */
	toString()
	{
		const outputArray = [];

		outputArray.push(padNumber(this.year, 4));
		outputArray.push(padNumber(this.month, 2));
		outputArray.push(padNumber(this.day, 2));
		outputArray.push(padNumber(this.hour, 2));
		outputArray.push(padNumber(this.minute, 2));
		outputArray.push(padNumber(this.second, 2));
		if(this.millisecond !== 0)
		{
			outputArray.push(".");
			outputArray.push(padNumber(this.millisecond, 3));
		}
		outputArray.push("Z");

		return outputArray.join("");
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "GeneralizedTime";
	}
	//**********************************************************************************
	/**
	 * Convertion for the block to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		let object = {};
		
		//region Seems at the moment (Sep 2016) there is no way how to check method is supported in "super" object
		try
		{
			object = super.toJSON();
		}
		catch(ex){}
		//endregion

		object.year = this.year;
		object.month = this.month;
		object.day = this.day;
		object.hour = this.hour;
		object.minute = this.minute;
		object.second = this.second;
		object.millisecond = this.millisecond;

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends Utf8String
 */
class DATE extends Utf8String
{
	//**********************************************************************************
	/**
	 * Constructor for "DATE" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 31; // DATE
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "DATE";
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends Utf8String
 */
class TimeOfDay extends Utf8String
{
	//**********************************************************************************
	/**
	 * Constructor for "TimeOfDay" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 32; // TimeOfDay
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "TimeOfDay";
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends Utf8String
 */
class DateTime extends Utf8String
{
	//**********************************************************************************
	/**
	 * Constructor for "DateTime" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 33; // DateTime
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "DateTime";
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends Utf8String
 */
class Duration extends Utf8String
{
	//**********************************************************************************
	/**
	 * Constructor for "Duration" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 34; // Duration
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "Duration";
	}
	//**********************************************************************************
}
//**************************************************************************************
/**
 * @extends Utf8String
 */
class TIME extends Utf8String
{
	//**********************************************************************************
	/**
	 * Constructor for "Time" class
	 * @param {Object} [parameters={}]
	 */
	constructor(parameters = {})
	{
		super(parameters);

		this.idBlock.tagClass = 1; // UNIVERSAL
		this.idBlock.tagNumber = 14; // Time
	}
	//**********************************************************************************
	/**
	 * Aux function, need to get a block name. Need to have it here for inhiritence
	 * @returns {string}
	 */
	static blockName()
	{
		return "TIME";
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of special ASN.1 schema type Choice
//**************************************************************************************
class Choice
{
	//**********************************************************************************
	/**
	 * Constructor for "Choice" class
	 * @param {Object} [parameters={}]
	 * @property {Array} [value] Array of ASN.1 types for make a choice from
	 * @property {boolean} [optional]
	 */
	constructor(parameters = {})
	{
		this.value = getParametersValue(parameters, "value", []);
		this.optional = getParametersValue(parameters, "optional", false);
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of special ASN.1 schema type Any
//**************************************************************************************
class Any
{
	//**********************************************************************************
	/**
	 * Constructor for "Any" class
	 * @param {Object} [parameters={}]
	 * @property {string} [name]
	 * @property {boolean} [optional]
	 */
	constructor(parameters = {})
	{
		this.name = getParametersValue(parameters, "name", "");
		this.optional = getParametersValue(parameters, "optional", false);
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of special ASN.1 schema type Repeated
//**************************************************************************************
class Repeated
{
	//**********************************************************************************
	/**
	 * Constructor for "Repeated" class
	 * @param {Object} [parameters={}]
	 * @property {string} [name]
	 * @property {boolean} [optional]
	 */
	constructor(parameters = {})
	{
		this.name = getParametersValue(parameters, "name", "");
		this.optional = getParametersValue(parameters, "optional", false);
		this.value = getParametersValue(parameters, "value", new Any());
		this.local = getParametersValue(parameters, "local", false); // Could local or global array to store elements
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of special ASN.1 schema type RawData
//**************************************************************************************
/**
 * @description Special class providing ability to have "toBER/fromBER" for raw ArrayBuffer
 */
class RawData
{
	//**********************************************************************************
	/**
	 * Constructor for "Repeated" class
	 * @param {Object} [parameters={}]
	 * @property {string} [name]
	 * @property {boolean} [optional]
	 */
	constructor(parameters = {})
	{
		this.data = getParametersValue(parameters, "data", new ArrayBuffer(0));
	}
	//**********************************************************************************
	/**
	 * Base function for converting block from BER encoded array of bytes
	 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
	 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
	 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
	 * @returns {number} Offset after least decoded byte
	 */
	fromBER(inputBuffer, inputOffset, inputLength)
	{
		this.data = inputBuffer.slice(inputOffset, inputLength);
	}
	//**********************************************************************************
	/**
	 * Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)
	 * @param {boolean} [sizeOnly=false] Flag that we need only a size of encoding, not a real array of bytes
	 * @returns {ArrayBuffer}
	 */
	toBER(sizeOnly = false)
	{
		return this.data;
	}
	//**********************************************************************************
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Major ASN.1 BER decoding function
//**************************************************************************************
/**
 * Internal library function for decoding ASN.1 BER
 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
 * @returns {{offset: number, result: Object}}
 */
function LocalFromBER(inputBuffer, inputOffset, inputLength)
{
	const incomingOffset = inputOffset; // Need to store initial offset since "inputOffset" is changing in the function

	//region Local function changing a type for ASN.1 classes
	function localChangeType(inputObject, newType)
	{
		if(inputObject instanceof newType)
			return inputObject;

		const newObject = new newType();
		newObject.idBlock = inputObject.idBlock;
		newObject.lenBlock = inputObject.lenBlock;
		newObject.warnings = inputObject.warnings;
		//noinspection JSCheckFunctionSignatures
		newObject.valueBeforeDecode = inputObject.valueBeforeDecode.slice(0);

		return newObject;
	}
	//endregion

	//region Create a basic ASN.1 type since we need to return errors and warnings from the function
	let returnObject = new BaseBlock({}, Object);
	//endregion

	//region Basic check for parameters
	if(checkBufferParams(new LocalBaseBlock(), inputBuffer, inputOffset, inputLength) === false)
	{
		returnObject.error = "Wrong input parameters";
		return {
			offset: (-1),
			result: returnObject
		};
	}
	//endregion

	//region Getting Uint8Array from ArrayBuffer
	const intBuffer = new Uint8Array(inputBuffer, inputOffset, inputLength);
	//endregion

	//region Initial checks
	if(intBuffer.length === 0)
	{
		this.error = "Zero buffer length";
		return {
			offset: (-1),
			result: returnObject
		};
	}
	//endregion

	//region Decode indentifcation block of ASN.1 BER structure
	let resultOffset = returnObject.idBlock.fromBER(inputBuffer, inputOffset, inputLength);
	returnObject.warnings.concat(returnObject.idBlock.warnings);
	if(resultOffset === (-1))
	{
		returnObject.error = returnObject.idBlock.error;
		return {
			offset: (-1),
			result: returnObject
		};
	}

	inputOffset = resultOffset;
	inputLength -= returnObject.idBlock.blockLength;
	//endregion

	//region Decode length block of ASN.1 BER structure
	resultOffset = returnObject.lenBlock.fromBER(inputBuffer, inputOffset, inputLength);
	returnObject.warnings.concat(returnObject.lenBlock.warnings);
	if(resultOffset === (-1))
	{
		returnObject.error = returnObject.lenBlock.error;
		return {
			offset: (-1),
			result: returnObject
		};
	}

	inputOffset = resultOffset;
	inputLength -= returnObject.lenBlock.blockLength;
	//endregion

	//region Check for usign indefinite length form in encoding for primitive types
	if((returnObject.idBlock.isConstructed === false) &&
		(returnObject.lenBlock.isIndefiniteForm === true))
	{
		returnObject.error = "Indefinite length form used for primitive encoding form";
		return {
			offset: (-1),
			result: returnObject
		};
	}
	//endregion

	//region Switch ASN.1 block type
	let newASN1Type = BaseBlock;

	switch(returnObject.idBlock.tagClass)
	{
		//region UNIVERSAL
		case 1:
			//region Check for reserved tag numbers
			if((returnObject.idBlock.tagNumber >= 37) &&
				(returnObject.idBlock.isHexOnly === false))
			{
				returnObject.error = "UNIVERSAL 37 and upper tags are reserved by ASN.1 standard";
				return {
					offset: (-1),
					result: returnObject
				};
			}
			//endregion

			switch(returnObject.idBlock.tagNumber)
			{
				//region EndOfContent type
				case 0:
					//region Check for EndOfContent type
					if((returnObject.idBlock.isConstructed === true) &&
						(returnObject.lenBlock.length > 0))
					{
						returnObject.error = "Type [UNIVERSAL 0] is reserved";
						return {
							offset: (-1),
							result: returnObject
						};
					}
					//endregion

					newASN1Type = EndOfContent;

					break;
				//endregion
				//region Boolean type
				case 1:
					newASN1Type = Boolean;
					break;
				//endregion
				//region Integer type
				case 2:
					newASN1Type = Integer;
					break;
				//endregion
				//region BitString type
				case 3:
					newASN1Type = BitString;
					break;
				//endregion
				//region OctetString type
				case 4:
					newASN1Type = OctetString;
					break;
				//endregion
				//region Null type
				case 5:
					newASN1Type = Null;
					break;
				//endregion
				//region OBJECT IDENTIFIER type
				case 6:
					newASN1Type = ObjectIdentifier;
					break;
				//endregion
				//region Enumerated type
				case 10:
					newASN1Type = Enumerated;
					break;
				//endregion
				//region Utf8String type
				case 12:
					newASN1Type = Utf8String;
					break;
				//endregion
				//region Time type
				case 14:
					newASN1Type = TIME;
					break;
				//endregion
				//region ASN.1 reserved type
				case 15:
					returnObject.error = "[UNIVERSAL 15] is reserved by ASN.1 standard";
					return {
						offset: (-1),
						result: returnObject
					};
				//endregion
				//region Sequence type
				case 16:
					newASN1Type = Sequence;
					break;
				//endregion
				//region Set type
				case 17:
					newASN1Type = Set;
					break;
				//endregion
				//region NumericString type
				case 18:
					newASN1Type = NumericString;
					break;
				//endregion
				//region PrintableString type
				case 19:
					newASN1Type = PrintableString;
					break;
				//endregion
				//region TeletexString type
				case 20:
					newASN1Type = TeletexString;
					break;
				//endregion
				//region VideotexString type
				case 21:
					newASN1Type = VideotexString;
					break;
				//endregion
				//region IA5String type
				case 22:
					newASN1Type = IA5String;
					break;
				//endregion
				//region UTCTime type
				case 23:
					newASN1Type = UTCTime;
					break;
				//endregion
				//region GeneralizedTime type
				case 24:
					newASN1Type = GeneralizedTime;
					break;
				//endregion
				//region GraphicString type
				case 25:
					newASN1Type = GraphicString;
					break;
				//endregion
				//region VisibleString type
				case 26:
					newASN1Type = VisibleString;
					break;
				//endregion
				//region GeneralString type
				case 27:
					newASN1Type = GeneralString;
					break;
				//endregion
				//region UniversalString type
				case 28:
					newASN1Type = UniversalString;
					break;
				//endregion
				//region CharacterString type
				case 29:
					newASN1Type = CharacterString;
					break;
				//endregion
				//region BmpString type
				case 30:
					newASN1Type = BmpString;
					break;
				//endregion
				//region DATE type
				case 31:
					newASN1Type = DATE;
					break;
				//endregion
				//region TimeOfDay type
				case 32:
					newASN1Type = TimeOfDay;
					break;
				//endregion
				//region Date-Time type
				case 33:
					newASN1Type = DateTime;
					break;
				//endregion
				//region Duration type
				case 34:
					newASN1Type = Duration;
					break;
				//endregion
				//region default
				default:
					{
						let newObject;

						if(returnObject.idBlock.isConstructed === true)
							newObject = new Constructed();
						else
							newObject = new Primitive();

						newObject.idBlock = returnObject.idBlock;
						newObject.lenBlock = returnObject.lenBlock;
						newObject.warnings = returnObject.warnings;

						returnObject = newObject;

						resultOffset = returnObject.fromBER(inputBuffer, inputOffset, inputLength);
					}
				//endregion
			}
			break;
		//endregion
		//region All other tag classes
		case 2: // APPLICATION
		case 3: // CONTEXT-SPECIFIC
		case 4: // PRIVATE
		default:
			{
				if(returnObject.idBlock.isConstructed === true)
					newASN1Type = Constructed;
				else
					newASN1Type = Primitive;
			}
		//endregion
	}
	//endregion

	//region Change type and perform BER decoding
	returnObject = localChangeType(returnObject, newASN1Type);
	resultOffset = returnObject.fromBER(inputBuffer, inputOffset, (returnObject.lenBlock.isIndefiniteForm === true) ? inputLength : returnObject.lenBlock.length);
	//endregion

	//region Coping incoming buffer for entire ASN.1 block
	returnObject.valueBeforeDecode = inputBuffer.slice(incomingOffset, incomingOffset + returnObject.blockLength);
	//endregion

	return {
		offset: resultOffset,
		result: returnObject
	};
}
//**************************************************************************************
/**
 * Major function for decoding ASN.1 BER array into internal library structuries
 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array of bytes
 */
function fromBER(inputBuffer)
{
	if(inputBuffer.byteLength === 0)
	{
		const result = new BaseBlock({}, Object);
		result.error = "Input buffer has zero length";

		return {
			offset: (-1),
			result
		};
	}

	return LocalFromBER(inputBuffer, 0, inputBuffer.byteLength);
}
//**************************************************************************************
//endregion
//**************************************************************************************
//region Major scheme verification function
//**************************************************************************************
/**
 * Compare of two ASN.1 object trees
 * @param {!Object} root Root of input ASN.1 object tree
 * @param {!Object} inputData Input ASN.1 object tree
 * @param {!Object} inputSchema Input ASN.1 schema to compare with
 * @return {{verified: boolean}|{verified:boolean, result: Object}}
 */
function compareSchema(root, inputData, inputSchema)
{
	//region Special case for Choice schema element type
	if(inputSchema instanceof Choice)
	{
		const choiceResult = false;

		for(let j = 0; j < inputSchema.value.length; j++)
		{
			const result = compareSchema(root, inputData, inputSchema.value[j]);
			if(result.verified === true)
			{
				return {
					verified: true,
					result: root
				};
			}
		}

		if(choiceResult === false)
		{
			const _result = {
				verified: false,
				result: {
					error: "Wrong values for Choice type"
				}
			};

			if(inputSchema.hasOwnProperty("name"))
				_result.name = inputSchema.name;

			return _result;
		}
	}
	//endregion

	//region Special case for Any schema element type
	if(inputSchema instanceof Any)
	{
		//region Add named component of ASN.1 schema
		if(inputSchema.hasOwnProperty("name"))
			root[inputSchema.name] = inputData;
		//endregion

		return {
			verified: true,
			result: root
		};
	}
	//endregion

	//region Initial check
	if((root instanceof Object) === false)
	{
		return {
			verified: false,
			result: { error: "Wrong root object" }
		};
	}

	if((inputData instanceof Object) === false)
	{
		return {
			verified: false,
			result: { error: "Wrong ASN.1 data" }
		};
	}

	if((inputSchema instanceof Object) === false)
	{
		return {
			verified: false,
			result: { error: "Wrong ASN.1 schema" }
		};
	}

	if(("idBlock" in inputSchema) === false)
	{
		return {
			verified: false,
			result: { error: "Wrong ASN.1 schema" }
		};
	}
	//endregion

	//region Comparing idBlock properties in ASN.1 data and ASN.1 schema
	//region Encode and decode ASN.1 schema idBlock
	/// <remarks>This encoding/decoding is neccessary because could be an errors in schema definition</remarks>
	if(("fromBER" in inputSchema.idBlock) === false)
	{
		return {
			verified: false,
			result: { error: "Wrong ASN.1 schema" }
		};
	}

	if(("toBER" in inputSchema.idBlock) === false)
	{
		return {
			verified: false,
			result: { error: "Wrong ASN.1 schema" }
		};
	}

	const encodedId = inputSchema.idBlock.toBER(false);
	if(encodedId.byteLength === 0)
	{
		return {
			verified: false,
			result: { error: "Error encoding idBlock for ASN.1 schema" }
		};
	}

	const decodedOffset = inputSchema.idBlock.fromBER(encodedId, 0, encodedId.byteLength);
	if(decodedOffset === (-1))
	{
		return {
			verified: false,
			result: { error: "Error decoding idBlock for ASN.1 schema" }
		};
	}
	//endregion

	//region tagClass
	if(inputSchema.idBlock.hasOwnProperty("tagClass") === false)
	{
		return {
			verified: false,
			result: { error: "Wrong ASN.1 schema" }
		};
	}

	if(inputSchema.idBlock.tagClass !== inputData.idBlock.tagClass)
	{
		return {
			verified: false,
			result: root
		};
	}
	//endregion
	//region tagNumber
	if(inputSchema.idBlock.hasOwnProperty("tagNumber") === false)
	{
		return {
			verified: false,
			result: { error: "Wrong ASN.1 schema" }
		};
	}

	if(inputSchema.idBlock.tagNumber !== inputData.idBlock.tagNumber)
	{
		return {
			verified: false,
			result: root
		};
	}
	//endregion
	//region isConstructed
	if(inputSchema.idBlock.hasOwnProperty("isConstructed") === false)
	{
		return {
			verified: false,
			result: { error: "Wrong ASN.1 schema" }
		};
	}

	if(inputSchema.idBlock.isConstructed !== inputData.idBlock.isConstructed)
	{
		return {
			verified: false,
			result: root
		};
	}
	//endregion
	//region isHexOnly
	if(("isHexOnly" in inputSchema.idBlock) === false) // Since 'isHexOnly' is an inhirited property
	{
		return {
			verified: false,
			result: { error: "Wrong ASN.1 schema" }
		};
	}

	if(inputSchema.idBlock.isHexOnly !== inputData.idBlock.isHexOnly)
	{
		return {
			verified: false,
			result: root
		};
	}
	//endregion
	//region valueHex
	if(inputSchema.idBlock.isHexOnly === true)
	{
		if(("valueHex" in inputSchema.idBlock) === false) // Since 'valueHex' is an inhirited property
		{
			return {
				verified: false,
				result: { error: "Wrong ASN.1 schema" }
			};
		}

		const schemaView = new Uint8Array(inputSchema.idBlock.valueHex);
		const asn1View = new Uint8Array(inputData.idBlock.valueHex);

		if(schemaView.length !== asn1View.length)
		{
			return {
				verified: false,
				result: root
			};
		}

		for(let i = 0; i < schemaView.length; i++)
		{
			if(schemaView[i] !== asn1View[1])
			{
				return {
					verified: false,
					result: root
				};
			}
		}
	}
	//endregion
	//endregion

	//region Add named component of ASN.1 schema
	if(inputSchema.hasOwnProperty("name"))
	{
		inputSchema.name = inputSchema.name.replace(/^\s+|\s+$/g, "");
		if(inputSchema.name !== "")
			root[inputSchema.name] = inputData;
	}
	//endregion

	//region Getting next ASN.1 block for comparition
	if(inputSchema.idBlock.isConstructed === true)
	{
		let admission = 0;
		let result = { verified: false };

		let maxLength = inputSchema.valueBlock.value.length;

		if(maxLength > 0)
		{
			if(inputSchema.valueBlock.value[0] instanceof Repeated)
				maxLength = inputData.valueBlock.value.length;
		}

		//region Special case when constructive value has no elements
		if(maxLength === 0)
		{
			return {
				verified: true,
				result: root
			};
		}
		//endregion

		//region Special case when "inputData" has no values and "inputSchema" has all optional values
		if((inputData.valueBlock.value.length === 0) &&
			(inputSchema.valueBlock.value.length !== 0))
		{
			let _optional = true;

			for(let i = 0; i < inputSchema.valueBlock.value.length; i++)
				_optional = _optional && (inputSchema.valueBlock.value[i].optional || false);

			if(_optional === true)
			{
				return {
					verified: true,
					result: root
				};
			}

			//region Delete early added name of block
			if(inputSchema.hasOwnProperty("name"))
			{
				inputSchema.name = inputSchema.name.replace(/^\s+|\s+$/g, "");
				if(inputSchema.name !== "")
					delete root[inputSchema.name];
			}
			//endregion

			root.error = "Inconsistent object length";

			return {
				verified: false,
				result: root
			};
		}
		//endregion

		for(let i = 0; i < maxLength; i++)
		{
			//region Special case when there is an "optional" element of ASN.1 schema at the end
			if((i - admission) >= inputData.valueBlock.value.length)
			{
				if(inputSchema.valueBlock.value[i].optional === false)
				{
					const _result = {
						verified: false,
						result: root
					};

					root.error = "Inconsistent length between ASN.1 data and schema";

					//region Delete early added name of block
					if(inputSchema.hasOwnProperty("name"))
					{
						inputSchema.name = inputSchema.name.replace(/^\s+|\s+$/g, "");
						if(inputSchema.name !== "")
						{
							delete root[inputSchema.name];
							_result.name = inputSchema.name;
						}
					}
					//endregion

					return _result;
				}
			}
			//endregion
			else
			{
				//region Special case for Repeated type of ASN.1 schema element
				if(inputSchema.valueBlock.value[0] instanceof Repeated)
				{
					result = compareSchema(root, inputData.valueBlock.value[i], inputSchema.valueBlock.value[0].value);
					if(result.verified === false)
					{
						if(inputSchema.valueBlock.value[0].optional === true)
							admission++;
						else
						{
							//region Delete early added name of block
							if(inputSchema.hasOwnProperty("name"))
							{
								inputSchema.name = inputSchema.name.replace(/^\s+|\s+$/g, "");
								if(inputSchema.name !== "")
									delete root[inputSchema.name];
							}
							//endregion

							return result;
						}
					}

					if(("name" in inputSchema.valueBlock.value[0]) && (inputSchema.valueBlock.value[0].name.length > 0))
					{
						let arrayRoot = {};

						if(("local" in inputSchema.valueBlock.value[0]) && (inputSchema.valueBlock.value[0].local === true))
							arrayRoot = inputData;
						else
							arrayRoot = root;

						if(typeof arrayRoot[inputSchema.valueBlock.value[0].name] === "undefined")
							arrayRoot[inputSchema.valueBlock.value[0].name] = [];

						arrayRoot[inputSchema.valueBlock.value[0].name].push(inputData.valueBlock.value[i]);
					}
				}
				//endregion
				else
				{
					result = compareSchema(root, inputData.valueBlock.value[i - admission], inputSchema.valueBlock.value[i]);
					if(result.verified === false)
					{
						if(inputSchema.valueBlock.value[i].optional === true)
							admission++;
						else
						{
							//region Delete early added name of block
							if(inputSchema.hasOwnProperty("name"))
							{
								inputSchema.name = inputSchema.name.replace(/^\s+|\s+$/g, "");
								if(inputSchema.name !== "")
									delete root[inputSchema.name];
							}
							//endregion

							return result;
						}
					}
				}
			}
		}

		if(result.verified === false) // The situation may take place if last element is "optional" and verification failed
		{
			const _result = {
				verified: false,
				result: root
			};

			//region Delete early added name of block
			if(inputSchema.hasOwnProperty("name"))
			{
				inputSchema.name = inputSchema.name.replace(/^\s+|\s+$/g, "");
				if(inputSchema.name !== "")
				{
					delete root[inputSchema.name];
					_result.name = inputSchema.name;
				}
			}
			//endregion

			return _result;
		}

		return {
			verified: true,
			result: root
		};
	}
	//endregion
	//region Ability to parse internal value for primitive-encoded value (value of OctetString, for example)
	if(("primitiveSchema" in inputSchema) &&
		("valueHex" in inputData.valueBlock))
	{
		//region Decoding of raw ASN.1 data
		const asn1 = fromBER(inputData.valueBlock.valueHex);
		if(asn1.offset === (-1))
		{
			const _result = {
				verified: false,
				result: asn1.result
			};

			//region Delete early added name of block
			if(inputSchema.hasOwnProperty("name"))
			{
				inputSchema.name = inputSchema.name.replace(/^\s+|\s+$/g, "");
				if(inputSchema.name !== "")
				{
					delete root[inputSchema.name];
					_result.name = inputSchema.name;
				}
			}
			//endregion

			return _result;
		}
		//endregion

		return compareSchema(root, asn1.result, inputSchema.primitiveSchema);
	}

	return {
		verified: true,
		result: root
	};
	//endregion
}
//**************************************************************************************
//noinspection JSUnusedGlobalSymbols
/**
 * ASN.1 schema verification for ArrayBuffer data
 * @param {!ArrayBuffer} inputBuffer Input BER-encoded ASN.1 data
 * @param {!Object} inputSchema Input ASN.1 schema to verify against to
 * @return {{verified: boolean}|{verified:boolean, result: Object}}
 */

//**************************************************************************************
//endregion
//**************************************************************************************
//region Major function converting JSON to ASN.1 objects
//**************************************************************************************
//noinspection JSUnusedGlobalSymbols
/**
 * Converting from JSON to ASN.1 objects
 * @param {string|Object} json JSON string or object to convert to ASN.1 objects
 */

//**************************************************************************************
//endregion
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class AlgorithmIdentifier
{
	//**********************************************************************************
	/**
	 * Constructor for AlgorithmIdentifier class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 * @property {string} [algorithmId] ObjectIdentifier for algorithm (string representation)
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {string}
		 * @description ObjectIdentifier for algorithm (string representation)
		 */
		this.algorithmId = getParametersValue(parameters, "algorithmId", AlgorithmIdentifier.defaultValues("algorithmId"));

		if("algorithmParams" in parameters)
			/**
			 * @type {Object}
			 * @description Any algorithm parameters
			 */
			this.algorithmParams = getParametersValue(parameters, "algorithmParams", AlgorithmIdentifier.defaultValues("algorithmParams"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "algorithmId":
				return "";
			case "algorithmParams":
				return new Any();
			default:
				throw new Error(`Invalid member name for AlgorithmIdentifier class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Compare values with default values for all class members
	 * @param {string} memberName String name for a class member
	 * @param {*} memberValue Value to compare with default value
	 */
	static compareWithDefault(memberName, memberValue)
	{
		switch(memberName)
		{
			case "algorithmId":
				return (memberValue === "");
			case "algorithmParams":
				return (memberValue instanceof Any);
			default:
				throw new Error(`Invalid member name for AlgorithmIdentifier class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//AlgorithmIdentifier  ::=  Sequence  {
		//    algorithm               OBJECT IDENTIFIER,
		//    parameters              ANY DEFINED BY algorithm OPTIONAL  }

		/**
		 * @type {Object}
		 * @property {string} algorithmIdentifier ObjectIdentifier for the algorithm
		 * @property {string} algorithmParams Any algorithm parameters
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			optional: (names.optional || false),
			value: [
				new ObjectIdentifier({ name: (names.algorithmIdentifier || "") }),
				new Any({ name: (names.algorithmParams || ""), optional: true })
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		/**
		 * @type {{verified: boolean}|{verified: boolean, result: {algorithm: Object, params: Object}}}
		 */
		const asn1 = compareSchema(schema,
			schema,
			AlgorithmIdentifier.schema({
				names: {
					algorithmIdentifier: "algorithm",
					algorithmParams: "params"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for AlgorithmIdentifier");
		//endregion

		//region Get internal properties from parsed schema
		this.algorithmId = asn1.result.algorithm.valueBlock.toString();
		if("params" in asn1.result)
			this.algorithmParams = asn1.result.params;
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Create array for output sequence
		const outputArray = [];
		
		outputArray.push(new ObjectIdentifier({ value: this.algorithmId }));
		if(("algorithmParams" in this) && ((this.algorithmParams instanceof Any) === false))
			outputArray.push(this.algorithmParams);
		//endregion
		
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: outputArray
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		const object = {
			algorithmId: this.algorithmId
		};

		if(("algorithmParams" in this) && ((this.algorithmParams instanceof Any) === false))
			object.algorithmParams = this.algorithmParams.toJSON();

		return object;
	}
	//**********************************************************************************
	/**
	 * Check that two "AlgorithmIdentifiers" are equal
	 * @param {AlgorithmIdentifier} algorithmIdentifier
	 * @returns {boolean}
	 */
	isEqual(algorithmIdentifier)
	{
		//region Check input type
		if((algorithmIdentifier instanceof AlgorithmIdentifier) === false)
			return false;
		//endregion

		//region Check "algorithm_id"
		if(this.algorithmId !== algorithmIdentifier.algorithmId)
			return false;
		//endregion

		//region Check "algorithm_params"
		if("algorithmParams" in this)
		{
			if("algorithmParams" in algorithmIdentifier)
				return JSON.stringify(this.algorithmParams) === JSON.stringify(algorithmIdentifier.algorithmParams);

			return false;
		}

		if("algorithmParams" in algorithmIdentifier)
			return false;
		//endregion

		return true;
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5480
 */
class ECPublicKey
{
	//**********************************************************************************
	/**
	 * Constructor for ECCPublicKey class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {ArrayBuffer}
		 * @description type
		 */
		this.x = getParametersValue(parameters, "x", ECPublicKey.defaultValues("x"));
		/**
		 * @type {ArrayBuffer}
		 * @description values
		 */
		this.y = getParametersValue(parameters, "y", ECPublicKey.defaultValues("y"));
		/**
		 * @type {string}
		 * @description namedCurve
		 */
		this.namedCurve = getParametersValue(parameters, "namedCurve", ECPublicKey.defaultValues("namedCurve"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
		//region If input argument array contains "json" for this object
		if("json" in parameters)
			this.fromJSON(parameters.json);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "x":
			case "y":
				return new ArrayBuffer(0);
			case "namedCurve":
				return "";
			default:
				throw new Error(`Invalid member name for ECCPublicKey class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Compare values with default values for all class members
	 * @param {string} memberName String name for a class member
	 * @param {*} memberValue Value to compare with default value
	 */
	static compareWithDefault(memberName, memberValue)
	{
		switch(memberName)
		{
			case "x":
			case "y":
				return (isEqualBuffer(memberValue, ECPublicKey.defaultValues(memberName)));
			case "namedCurve":
				return (memberValue === "");
			default:
				throw new Error(`Invalid member name for ECCPublicKey class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		return new RawData();
	}
	//**********************************************************************************
	/**
	 * Convert ArrayBuffer into current class
	 * @param {!ArrayBuffer} schema Special case: schema is an ArrayBuffer
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		if((schema instanceof ArrayBuffer) === false)
			throw new Error("Object's schema was not verified against input data for ECPublicKey");

		const view = new Uint8Array(schema);
		if(view[0] !== 0x04)
			throw new Error("Object's schema was not verified against input data for ECPublicKey");
		//endregion

		//region Get internal properties from parsed schema
		let coordinateLength;

		switch(this.namedCurve)
		{
			case "1.2.840.10045.3.1.7": // P-256
				coordinateLength = 32;
				break;
			case "1.3.132.0.34": // P-384
				coordinateLength = 48;
				break;
			case "1.3.132.0.35": // P-521
				coordinateLength = 66;
				break;
			default:
				throw new Error(`Incorrect curve OID: ${this.namedCurve}`);
		}

		if(schema.byteLength !== (coordinateLength * 2 + 1))
			throw new Error("Object's schema was not verified against input data for ECPublicKey");
		
		this.x = schema.slice(1, coordinateLength + 1);
		this.y = schema.slice(1 + coordinateLength, coordinateLength * 2 + 1);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		return new RawData({ data: utilConcatBuf(
			(new Uint8Array([0x04])).buffer,
			this.x,
			this.y
		)
		});
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		let crvName = "";

		switch(this.namedCurve)
		{
			case "1.2.840.10045.3.1.7": // P-256
				crvName = "P-256";
				break;
			case "1.3.132.0.34": // P-384
				crvName = "P-384";
				break;
			case "1.3.132.0.35": // P-521
				crvName = "P-521";
				break;
			default:
		}

		return {
			crv: crvName,
			x: toBase64(arrayBufferToString(this.x), true, true, false),
			y: toBase64(arrayBufferToString(this.y), true, true, false)
		};
	}
	//**********************************************************************************
	/**
	 * Convert JSON value into current object
	 * @param {Object} json
	 */
	fromJSON(json)
	{
		let coodinateLength = 0;

		if("crv" in json)
		{
			switch(json.crv.toUpperCase())
			{
				case "P-256":
					this.namedCurve = "1.2.840.10045.3.1.7";
					coodinateLength = 32;
					break;
				case "P-384":
					this.namedCurve = "1.3.132.0.34";
					coodinateLength = 48;
					break;
				case "P-521":
					this.namedCurve = "1.3.132.0.35";
					coodinateLength = 66;
					break;
				default:
			}
		}
		else
			throw new Error("Absent mandatory parameter \"crv\"");

		if("x" in json)
		{
			const convertBuffer = stringToArrayBuffer(fromBase64(json.x, true));
			
			if(convertBuffer.byteLength < coodinateLength)
			{
				this.x = new ArrayBuffer(coodinateLength);
				const view = new Uint8Array(this.x);
				const convertBufferView = new Uint8Array(convertBuffer);
				view.set(convertBufferView, 1);
			}
			else
				this.x = convertBuffer.slice(0, coodinateLength);
		}
		else
			throw new Error("Absent mandatory parameter \"x\"");

		if("y" in json)
		{
			const convertBuffer = stringToArrayBuffer(fromBase64(json.y, true));
			
			if(convertBuffer.byteLength < coodinateLength)
			{
				this.y = new ArrayBuffer(coodinateLength);
				const view = new Uint8Array(this.y);
				const convertBufferView = new Uint8Array(convertBuffer);
				view.set(convertBufferView, 1);
			}
			else
				this.y = convertBuffer.slice(0, coodinateLength);
		}
		else
			throw new Error("Absent mandatory parameter \"y\"");
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC3447
 */
class RSAPublicKey
{
	//**********************************************************************************
	/**
	 * Constructor for RSAPublicKey class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 * @property {Integer} [modulus]
	 * @property {Integer} [publicExponent]
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Integer}
		 * @description Modulus part of RSA public key
		 */
		this.modulus = getParametersValue(parameters, "modulus", RSAPublicKey.defaultValues("modulus"));
		/**
		 * @type {Integer}
		 * @description Public exponent of RSA public key
		 */
		this.publicExponent = getParametersValue(parameters, "publicExponent", RSAPublicKey.defaultValues("publicExponent"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
		//region If input argument array contains "json" for this object
		if("json" in parameters)
			this.fromJSON(parameters.json);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "modulus":
				return new Integer();
			case "publicExponent":
				return new Integer();
			default:
				throw new Error(`Invalid member name for RSAPublicKey class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//RSAPublicKey ::= Sequence {
		//    modulus           Integer,  -- n
		//    publicExponent    Integer   -- e
		//}

		/**
		 * @type {Object}
		 * @property {string} utcTimeName Name for "utcTimeName" choice
		 * @property {string} generalTimeName Name for "generalTimeName" choice
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Integer({ name: (names.modulus || "") }),
				new Integer({ name: (names.publicExponent || "") })
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			RSAPublicKey.schema({
				names: {
					modulus: "modulus",
					publicExponent: "publicExponent"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for RSAPublicKey");
		//endregion

		//region Get internal properties from parsed schema
		this.modulus = asn1.result.modulus.convertFromDER(256);
		this.publicExponent = asn1.result.publicExponent;
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: [
				this.modulus.convertToDER(),
				this.publicExponent
			]
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		return {
			n: toBase64(arrayBufferToString(this.modulus.valueBlock.valueHex), true, true, true),
			e: toBase64(arrayBufferToString(this.publicExponent.valueBlock.valueHex), true, true, true)
		};
	}
	//**********************************************************************************
	/**
	 * Convert JSON value into current object
	 * @param {Object} json
	 */
	fromJSON(json)
	{
		if("n" in json)
		{
			const array = stringToArrayBuffer(fromBase64(json.n, true));
			this.modulus = new Integer({ valueHex: array.slice(0, Math.pow(2, nearestPowerOf2(array.byteLength))) });
		}
		else
			throw new Error("Absent mandatory parameter \"n\"");

		if("e" in json)
			this.publicExponent = new Integer({ valueHex: stringToArrayBuffer(fromBase64(json.e, true)).slice(0, 3) });
		else
			throw new Error("Absent mandatory parameter \"e\"");
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class PublicKeyInfo 
{
	//**********************************************************************************
	/**
	 * Constructor for PublicKeyInfo class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {AlgorithmIdentifier}
		 * @description Algorithm identifier
		 */
		this.algorithm = getParametersValue(parameters, "algorithm", PublicKeyInfo.defaultValues("algorithm"));
		/**
		 * @type {BitString}
		 * @description Subject public key value
		 */
		this.subjectPublicKey = getParametersValue(parameters, "subjectPublicKey", PublicKeyInfo.defaultValues("subjectPublicKey"));
		
		if("parsedKey" in parameters)
			/**
			 * @type {ECPublicKey|RSAPublicKey}
			 * @description Parsed public key value
			 */
			this.parsedKey = getParametersValue(parameters, "parsedKey", PublicKeyInfo.defaultValues("parsedKey"));
		//endregion
		
		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
		//region If input argument array contains "json" for this object
		if("json" in parameters)
			this.fromJSON(parameters.json);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "algorithm":
				return new AlgorithmIdentifier();
			case "subjectPublicKey":
				return new BitString();
			default:
				throw new Error(`Invalid member name for PublicKeyInfo class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//SubjectPublicKeyInfo  ::=  Sequence  {
		//    algorithm            AlgorithmIdentifier,
		//    subjectPublicKey     BIT STRING  }
		
		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [algorithm]
		 * @property {string} [subjectPublicKey]
		 */
		const names = getParametersValue(parameters, "names", {});
		
		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				AlgorithmIdentifier.schema(names.algorithm || {}),
				new BitString({ name: (names.subjectPublicKey || "") })
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			PublicKeyInfo.schema({
				names: {
					algorithm: {
						names: {
							blockName: "algorithm"
						}
					},
					subjectPublicKey: "subjectPublicKey"
				}
			})
		);
		
		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for PUBLIC_KEY_INFO");
		//endregion
		
		//region Get internal properties from parsed schema
		this.algorithm = new AlgorithmIdentifier({ schema: asn1.result.algorithm });
		this.subjectPublicKey = asn1.result.subjectPublicKey;
		
		switch(this.algorithm.algorithmId)
		{
			case "1.2.840.10045.2.1": // ECDSA
				if("algorithmParams" in this.algorithm)
				{
					if(this.algorithm.algorithmParams instanceof ObjectIdentifier)
					{
						try
						{
							this.parsedKey = new ECPublicKey({
								namedCurve: this.algorithm.algorithmParams.valueBlock.toString(),
								schema: this.subjectPublicKey.valueBlock.valueHex
							});
						}
						catch(ex){} // Could be a problems during recognision of internal public key data here. Let's ignore them.
					}
				}
				break;
			case "1.2.840.113549.1.1.1": // RSA
				{
					const publicKeyASN1 = fromBER(this.subjectPublicKey.valueBlock.valueHex);
					if(publicKeyASN1.offset !== (-1))
					{
						try
						{
							this.parsedKey = new RSAPublicKey({ schema: publicKeyASN1.result });
						}
						catch(ex){} // Could be a problems during recognision of internal public key data here. Let's ignore them.
					}
				}
				break;
			default:
		}
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: [
				this.algorithm.toSchema(),
				this.subjectPublicKey
			]
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		//region Return common value in case we do not have enough info fo making JWK
		if(("parsedKey" in this) === false)
		{
			return {
				algorithm: this.algorithm.toJSON(),
				subjectPublicKey: this.subjectPublicKey.toJSON()
			};
		}
		//endregion
		
		//region Making JWK
		const jwk = {};
		
		switch(this.algorithm.algorithmId)
		{
			case "1.2.840.10045.2.1": // ECDSA
				jwk.kty = "EC";
				break;
			case "1.2.840.113549.1.1.1": // RSA
				jwk.kty = "RSA";
				break;
			default:
		}
		
		const publicKeyJWK = this.parsedKey.toJSON();
		
		for(const key of Object.keys(publicKeyJWK))
			jwk[key] = publicKeyJWK[key];
		
		return jwk;
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert JSON value into current object
	 * @param {Object} json
	 */
	fromJSON(json)
	{
		if("kty" in json)
		{
			switch(json.kty.toUpperCase())
			{
				case "EC":
					this.parsedKey = new ECPublicKey({ json });
					
					this.algorithm = new AlgorithmIdentifier({
						algorithmId: "1.2.840.10045.2.1",
						algorithmParams: new ObjectIdentifier({ value: this.parsedKey.namedCurve })
					});
					break;
				case "RSA":
					this.parsedKey = new RSAPublicKey({ json });
					
					this.algorithm = new AlgorithmIdentifier({
						algorithmId: "1.2.840.113549.1.1.1",
						algorithmParams: new Null()
					});
					break;
				default:
					throw new Error(`Invalid value for "kty" parameter: ${json.kty}`);
			}
			
			this.subjectPublicKey = new BitString({ valueHex: this.parsedKey.toSchema().toBER(false) });
		}
	}
	//**********************************************************************************
	importKey(publicKey)
	{
		//region Initial variables
		let sequence = Promise.resolve();
		const _this = this;
		//endregion
		
		//region Initial check
		if(typeof publicKey === "undefined")
			return Promise.reject("Need to provide publicKey input parameter");
		//endregion
		
		//region Get a "crypto" extension
		const crypto = getCrypto();
		if(typeof crypto === "undefined")
			return Promise.reject("Unable to create WebCrypto object");
		//endregion
		
		//region Export public key
		sequence = sequence.then(() =>
			crypto.exportKey("spki", publicKey));
		//endregion
		
		//region Initialize internal variables by parsing exported value
		sequence = sequence.then(
			/**
			 * @param {ArrayBuffer} exportedKey
			 */
			exportedKey =>
			{
				const asn1 = fromBER(exportedKey);
				try
				{
					_this.fromSchema(asn1.result);
				}
				catch(exception)
				{
					return Promise.reject("Error during initializing object from schema");
				}
				
				return undefined;
			},
			error => Promise.reject(`Error during exporting public key: ${error}`)
		);
		//endregion
		
		return sequence;
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC2986
 */
class Attribute {
	//**********************************************************************************
	/**
	 * Constructor for Attribute class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {string}
		 * @description type
		 */
		this.type = getParametersValue(parameters, "type", Attribute.defaultValues("type"));
		/**
		 * @type {Array}
		 * @description values
		 */
		this.values = getParametersValue(parameters, "values", Attribute.defaultValues("values"));
		//endregion
		
		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "type":
				return "";
			case "values":
				return [];
			default:
				throw new Error(`Invalid member name for Attribute class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Compare values with default values for all class members
	 * @param {string} memberName String name for a class member
	 * @param {*} memberValue Value to compare with default value
	 */
	static compareWithDefault(memberName, memberValue)
	{
		switch(memberName)
		{
			case "type":
				return (memberValue === "");
			case "values":
				return (memberValue.length === 0);
			default:
				throw new Error(`Invalid member name for Attribute class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		// Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
		//    type   ATTRIBUTE.&id({IOSet}),
		//    values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
		//}
		
		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [type]
		 * @property {string} [setName]
		 * @property {string} [values]
		 */
		const names = getParametersValue(parameters, "names", {});
		
		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new ObjectIdentifier({ name: (names.type || "") }),
				new Set({
					name: (names.setName || ""),
					value: [
						new Repeated({
							name: (names.values || ""),
							value: new Any()
						})
					]
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			Attribute.schema({
				names: {
					type: "type",
					values: "values"
				}
			})
		);
		
		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for ATTRIBUTE");
		//endregion
		
		//region Get internal properties from parsed schema
		this.type = asn1.result.type.valueBlock.toString();
		this.values = asn1.result.values;
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: [
				new ObjectIdentifier({ value: this.type }),
				new Set({
					value: this.values
				})
			]
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		return {
			type: this.type,
			values: Array.from(this.values, element => element.toJSON())
		};
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5915
 */
class ECPrivateKey
{
	//**********************************************************************************
	/**
	 * Constructor for ECCPrivateKey class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {number}
		 * @description version
		 */
		this.version = getParametersValue(parameters, "version", ECPrivateKey.defaultValues("version"));
		/**
		 * @type {OctetString}
		 * @description privateKey
		 */
		this.privateKey = getParametersValue(parameters, "privateKey", ECPrivateKey.defaultValues("privateKey"));

		if("namedCurve" in parameters)
			/**
			 * @type {string}
			 * @description namedCurve
			 */
			this.namedCurve = getParametersValue(parameters, "namedCurve", ECPrivateKey.defaultValues("namedCurve"));

		if("publicKey" in parameters)
			/**
			 * @type {ECPublicKey}
			 * @description publicKey
			 */
			this.publicKey = getParametersValue(parameters, "publicKey", ECPrivateKey.defaultValues("publicKey"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
		//region If input argument array contains "json" for this object
		if("json" in parameters)
			this.fromJSON(parameters.json);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "version":
				return 1;
			case "privateKey":
				return new OctetString();
			case "namedCurve":
				return "";
			case "publicKey":
				return new ECPublicKey();
			default:
				throw new Error(`Invalid member name for ECCPrivateKey class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Compare values with default values for all class members
	 * @param {string} memberName String name for a class member
	 * @param {*} memberValue Value to compare with default value
	 */
	static compareWithDefault(memberName, memberValue)
	{
		switch(memberName)
		{
			case "version":
				return (memberValue === ECPrivateKey.defaultValues(memberName));
			case "privateKey":
				return (memberValue.isEqual(ECPrivateKey.defaultValues(memberName)));
			case "namedCurve":
				return (memberValue === "");
			case "publicKey":
				return ((ECPublicKey.compareWithDefault("namedCurve", memberValue.namedCurve)) &&
						(ECPublicKey.compareWithDefault("x", memberValue.x)) &&
						(ECPublicKey.compareWithDefault("y", memberValue.y)));
			default:
				throw new Error(`Invalid member name for ECCPrivateKey class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		// ECPrivateKey ::= SEQUENCE {
		// version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
		// privateKey     OCTET STRING,
		// parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
		// publicKey  [1] BIT STRING OPTIONAL
		// }

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [version]
		 * @property {string} [privateKey]
		 * @property {string} [namedCurve]
		 * @property {string} [publicKey]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Integer({ name: (names.version || "") }),
				new OctetString({ name: (names.privateKey || "") }),
				new Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [
						new ObjectIdentifier({ name: (names.namedCurve || "") })
					]
				}),
				new Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					value: [
						new BitString({ name: (names.publicKey || "") })
					]
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			ECPrivateKey.schema({
				names: {
					version: "version",
					privateKey: "privateKey",
					namedCurve: "namedCurve",
					publicKey: "publicKey"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for ECPrivateKey");
		//endregion

		//region Get internal properties from parsed schema
		this.version = asn1.result.version.valueBlock.valueDec;
		this.privateKey = asn1.result.privateKey;

		if("namedCurve" in asn1.result)
			this.namedCurve = asn1.result.namedCurve.valueBlock.toString();

		if("publicKey" in asn1.result)
		{
			const publicKeyData = { schema: asn1.result.publicKey.valueBlock.valueHex };
			if("namedCurve" in this)
				publicKeyData.namedCurve = this.namedCurve;

			this.publicKey = new ECPublicKey(publicKeyData);
		}
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		const outputArray = [
			new Integer({ value: this.version }),
			this.privateKey
		];

		if("namedCurve" in this)
		{
			outputArray.push(new Constructed({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 0 // [0]
				},
				value: [
					new ObjectIdentifier({ value: this.namedCurve })
				]
			}));
		}

		if("publicKey" in this)
		{
			outputArray.push(new Constructed({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 1 // [1]
				},
				value: [
					new BitString({ valueHex: this.publicKey.toSchema().toBER(false) })
				]
			}));
		}

		return new Sequence({
			value: outputArray
		});
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		if((("namedCurve" in this) === false) || (ECPrivateKey.compareWithDefault("namedCurve", this.namedCurve)))
			throw new Error("Not enough information for making JSON: absent \"namedCurve\" value");

		let crvName = "";

		switch(this.namedCurve)
		{
			case "1.2.840.10045.3.1.7": // P-256
				crvName = "P-256";
				break;
			case "1.3.132.0.34": // P-384
				crvName = "P-384";
				break;
			case "1.3.132.0.35": // P-521
				crvName = "P-521";
				break;
			default:
		}

		const privateKeyJSON = {
			crv: crvName,
			d: toBase64(arrayBufferToString(this.privateKey.valueBlock.valueHex), true, true, false)
		};

		if("publicKey" in this)
		{
			const publicKeyJSON = this.publicKey.toJSON();

			privateKeyJSON.x = publicKeyJSON.x;
			privateKeyJSON.y = publicKeyJSON.y;
		}

		return privateKeyJSON;
	}
	//**********************************************************************************
	/**
	 * Convert JSON value into current object
	 * @param {Object} json
	 */
	fromJSON(json)
	{
		let coodinateLength = 0;

		if("crv" in json)
		{
			switch(json.crv.toUpperCase())
			{
				case "P-256":
					this.namedCurve = "1.2.840.10045.3.1.7";
					coodinateLength = 32;
					break;
				case "P-384":
					this.namedCurve = "1.3.132.0.34";
					coodinateLength = 48;
					break;
				case "P-521":
					this.namedCurve = "1.3.132.0.35";
					coodinateLength = 66;
					break;
				default:
			}
		}
		else
			throw new Error("Absent mandatory parameter \"crv\"");

		if("d" in json)
		{
			const convertBuffer = stringToArrayBuffer(fromBase64(json.d, true));
			
			if(convertBuffer.byteLength < coodinateLength)
			{
				const buffer = new ArrayBuffer(coodinateLength);
				const view = new Uint8Array(buffer);
				const convertBufferView = new Uint8Array(convertBuffer);
				view.set(convertBufferView, 1);
				
				this.privateKey = new OctetString({ valueHex: buffer });
			}
			else
				this.privateKey = new OctetString({ valueHex: convertBuffer.slice(0, coodinateLength) });
		}
		else
			throw new Error("Absent mandatory parameter \"d\"");

		if(("x" in json) && ("y" in json))
			this.publicKey = new ECPublicKey({ json });
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC3447
 */
class OtherPrimeInfo
{
	//**********************************************************************************
	/**
	 * Constructor for OtherPrimeInfo class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Integer}
		 * @description prime
		 */
		this.prime = getParametersValue(parameters, "prime", OtherPrimeInfo.defaultValues("prime"));
		/**
		 * @type {Integer}
		 * @description exponent
		 */
		this.exponent = getParametersValue(parameters, "exponent", OtherPrimeInfo.defaultValues("exponent"));
		/**
		 * @type {Integer}
		 * @description coefficient
		 */
		this.coefficient = getParametersValue(parameters, "coefficient", OtherPrimeInfo.defaultValues("coefficient"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
		//region If input argument array contains "json" for this object
		if("json" in parameters)
			this.fromJSON(parameters.json);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "prime":
				return new Integer();
			case "exponent":
				return new Integer();
			case "coefficient":
				return new Integer();
			default:
				throw new Error(`Invalid member name for OtherPrimeInfo class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//OtherPrimeInfo ::= Sequence {
		//    prime             Integer,  -- ri
		//    exponent          Integer,  -- di
		//    coefficient       Integer   -- ti
		//}

		/**
		 * @type {Object}
		 * @property {string} prime
		 * @property {string} exponent
		 * @property {string} coefficient
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Integer({ name: (names.prime || "") }),
				new Integer({ name: (names.exponent || "") }),
				new Integer({ name: (names.coefficient || "") })
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			OtherPrimeInfo.schema({
				names: {
					prime: "prime",
					exponent: "exponent",
					coefficient: "coefficient"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for OtherPrimeInfo");
		//endregion

		//region Get internal properties from parsed schema
		this.prime = asn1.result.prime.convertFromDER();
		this.exponent = asn1.result.exponent.convertFromDER();
		this.coefficient = asn1.result.coefficient.convertFromDER();
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: [
				this.prime.convertToDER(),
				this.exponent.convertToDER(),
				this.coefficient.convertToDER()
			]
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		return {
			r: toBase64(arrayBufferToString(this.prime.valueBlock.valueHex), true, true),
			d: toBase64(arrayBufferToString(this.exponent.valueBlock.valueHex), true, true),
			t: toBase64(arrayBufferToString(this.coefficient.valueBlock.valueHex), true, true)
		};
	}
	//**********************************************************************************
	/**
	 * Convert JSON value into current object
	 * @param {Object} json
	 */
	fromJSON(json)
	{
		if("r" in json)
			this.prime = new Integer({ valueHex: stringToArrayBuffer(fromBase64(json.r, true)) });
		else
			throw new Error("Absent mandatory parameter \"r\"");

		if("d" in json)
			this.exponent = new Integer({ valueHex: stringToArrayBuffer(fromBase64(json.d, true)) });
		else
			throw new Error("Absent mandatory parameter \"d\"");

		if("t" in json)
			this.coefficient = new Integer({ valueHex: stringToArrayBuffer(fromBase64(json.t, true)) });
		else
			throw new Error("Absent mandatory parameter \"t\"");
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC3447
 */
class RSAPrivateKey
{
	//**********************************************************************************
	/**
	 * Constructor for RSAPrivateKey class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {number}
		 * @description version
		 */
		this.version = getParametersValue(parameters, "version", RSAPrivateKey.defaultValues("version"));
		/**
		 * @type {Integer}
		 * @description modulus
		 */
		this.modulus = getParametersValue(parameters, "modulus", RSAPrivateKey.defaultValues("modulus"));
		/**
		 * @type {Integer}
		 * @description publicExponent
		 */
		this.publicExponent = getParametersValue(parameters, "publicExponent", RSAPrivateKey.defaultValues("publicExponent"));
		/**
		 * @type {Integer}
		 * @description privateExponent
		 */
		this.privateExponent = getParametersValue(parameters, "privateExponent", RSAPrivateKey.defaultValues("privateExponent"));
		/**
		 * @type {Integer}
		 * @description prime1
		 */
		this.prime1 = getParametersValue(parameters, "prime1", RSAPrivateKey.defaultValues("prime1"));
		/**
		 * @type {Integer}
		 * @description prime2
		 */
		this.prime2 = getParametersValue(parameters, "prime2", RSAPrivateKey.defaultValues("prime2"));
		/**
		 * @type {Integer}
		 * @description exponent1
		 */
		this.exponent1 = getParametersValue(parameters, "exponent1", RSAPrivateKey.defaultValues("exponent1"));
		/**
		 * @type {Integer}
		 * @description exponent2
		 */
		this.exponent2 = getParametersValue(parameters, "exponent2", RSAPrivateKey.defaultValues("exponent2"));
		/**
		 * @type {Integer}
		 * @description coefficient
		 */
		this.coefficient = getParametersValue(parameters, "coefficient", RSAPrivateKey.defaultValues("coefficient"));

		if("otherPrimeInfos" in parameters)
			/**
			 * @type {Array.<OtherPrimeInfo>}
			 * @description otherPrimeInfos
			 */
			this.otherPrimeInfos = getParametersValue(parameters, "otherPrimeInfos", RSAPrivateKey.defaultValues("otherPrimeInfos"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
		//region If input argument array contains "json" for this object
		if("json" in parameters)
			this.fromJSON(parameters.json);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "version":
				return 0;
			case "modulus":
				return new Integer();
			case "publicExponent":
				return new Integer();
			case "privateExponent":
				return new Integer();
			case "prime1":
				return new Integer();
			case "prime2":
				return new Integer();
			case "exponent1":
				return new Integer();
			case "exponent2":
				return new Integer();
			case "coefficient":
				return new Integer();
			case "otherPrimeInfos":
				return [];
			default:
				throw new Error(`Invalid member name for RSAPrivateKey class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//RSAPrivateKey ::= Sequence {
		//    version           Version,
		//    modulus           Integer,  -- n
		//    publicExponent    Integer,  -- e
		//    privateExponent   Integer,  -- d
		//    prime1            Integer,  -- p
		//    prime2            Integer,  -- q
		//    exponent1         Integer,  -- d mod (p-1)
		//    exponent2         Integer,  -- d mod (q-1)
		//    coefficient       Integer,  -- (inverse of q) mod p
		//    otherPrimeInfos   OtherPrimeInfos OPTIONAL
		//}
		//
		//OtherPrimeInfos ::= Sequence SIZE(1..MAX) OF OtherPrimeInfo

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [version]
		 * @property {string} [modulus]
		 * @property {string} [publicExponent]
		 * @property {string} [privateExponent]
		 * @property {string} [prime1]
		 * @property {string} [prime2]
		 * @property {string} [exponent1]
		 * @property {string} [exponent2]
		 * @property {string} [coefficient]
		 * @property {string} [otherPrimeInfosName]
		 * @property {Object} [otherPrimeInfo]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Integer({ name: (names.version || "") }),
				new Integer({ name: (names.modulus || "") }),
				new Integer({ name: (names.publicExponent || "") }),
				new Integer({ name: (names.privateExponent || "") }),
				new Integer({ name: (names.prime1 || "") }),
				new Integer({ name: (names.prime2 || "") }),
				new Integer({ name: (names.exponent1 || "") }),
				new Integer({ name: (names.exponent2 || "") }),
				new Integer({ name: (names.coefficient || "") }),
				new Sequence({
					optional: true,
					value: [
						new Repeated({
							name: (names.otherPrimeInfosName || ""),
							value: OtherPrimeInfo.schema(names.otherPrimeInfo || {})
						})
					]
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			RSAPrivateKey.schema({
				names: {
					version: "version",
					modulus: "modulus",
					publicExponent: "publicExponent",
					privateExponent: "privateExponent",
					prime1: "prime1",
					prime2: "prime2",
					exponent1: "exponent1",
					exponent2: "exponent2",
					coefficient: "coefficient",
					otherPrimeInfo: {
						names: {
							blockName: "otherPrimeInfos"
						}
					}
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for RSAPrivateKey");
		//endregion

		//region Get internal properties from parsed schema
		this.version = asn1.result.version.valueBlock.valueDec;
		this.modulus = asn1.result.modulus.convertFromDER(256);
		this.publicExponent = asn1.result.publicExponent;
		this.privateExponent = asn1.result.privateExponent.convertFromDER(256);
		this.prime1 = asn1.result.prime1.convertFromDER(128);
		this.prime2 = asn1.result.prime2.convertFromDER(128);
		this.exponent1 = asn1.result.exponent1.convertFromDER(128);
		this.exponent2 = asn1.result.exponent2.convertFromDER(128);
		this.coefficient = asn1.result.coefficient.convertFromDER(128);

		if("otherPrimeInfos" in asn1.result)
			this.otherPrimeInfos = Array.from(asn1.result.otherPrimeInfos, element => new OtherPrimeInfo({ schema: element }));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Create array for output sequence
		const outputArray = [];
		
		outputArray.push(new Integer({ value: this.version }));
		outputArray.push(this.modulus.convertToDER());
		outputArray.push(this.publicExponent);
		outputArray.push(this.privateExponent.convertToDER());
		outputArray.push(this.prime1.convertToDER());
		outputArray.push(this.prime2.convertToDER());
		outputArray.push(this.exponent1.convertToDER());
		outputArray.push(this.exponent2.convertToDER());
		outputArray.push(this.coefficient.convertToDER());
		
		if("otherPrimeInfos" in this)
		{
			outputArray.push(new Sequence({
				value: Array.from(this.otherPrimeInfos, element => element.toSchema())
			}));
		}
		//endregion
		
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: outputArray
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		const jwk = {
			n: toBase64(arrayBufferToString(this.modulus.valueBlock.valueHex), true, true, true),
			e: toBase64(arrayBufferToString(this.publicExponent.valueBlock.valueHex), true, true, true),
			d: toBase64(arrayBufferToString(this.privateExponent.valueBlock.valueHex), true, true, true),
			p: toBase64(arrayBufferToString(this.prime1.valueBlock.valueHex), true, true, true),
			q: toBase64(arrayBufferToString(this.prime2.valueBlock.valueHex), true, true, true),
			dp: toBase64(arrayBufferToString(this.exponent1.valueBlock.valueHex), true, true, true),
			dq: toBase64(arrayBufferToString(this.exponent2.valueBlock.valueHex), true, true, true),
			qi: toBase64(arrayBufferToString(this.coefficient.valueBlock.valueHex), true, true, true)
		};

		if("otherPrimeInfos" in this)
			jwk.oth = Array.from(this.otherPrimeInfos, element => element.toJSON());

		return jwk;
	}
	//**********************************************************************************
	/**
	 * Convert JSON value into current object
	 * @param {Object} json
	 */
	fromJSON(json)
	{
		if("n" in json)
			this.modulus = new Integer({ valueHex: stringToArrayBuffer(fromBase64(json.n, true, true)) });
		else
			throw new Error("Absent mandatory parameter \"n\"");

		if("e" in json)
			this.publicExponent = new Integer({ valueHex: stringToArrayBuffer(fromBase64(json.e, true, true)) });
		else
			throw new Error("Absent mandatory parameter \"e\"");

		if("d" in json)
			this.privateExponent = new Integer({ valueHex: stringToArrayBuffer(fromBase64(json.d, true, true)) });
		else
			throw new Error("Absent mandatory parameter \"d\"");

		if("p" in json)
			this.prime1 = new Integer({ valueHex: stringToArrayBuffer(fromBase64(json.p, true, true)) });
		else
			throw new Error("Absent mandatory parameter \"p\"");

		if("q" in json)
			this.prime2 = new Integer({ valueHex: stringToArrayBuffer(fromBase64(json.q, true, true)) });
		else
			throw new Error("Absent mandatory parameter \"q\"");

		if("dp" in json)
			this.exponent1 = new Integer({ valueHex: stringToArrayBuffer(fromBase64(json.dp, true, true)) });
		else
			throw new Error("Absent mandatory parameter \"dp\"");

		if("dq" in json)
			this.exponent2 = new Integer({ valueHex: stringToArrayBuffer(fromBase64(json.dq, true, true)) });
		else
			throw new Error("Absent mandatory parameter \"dq\"");

		if("qi" in json)
			this.coefficient = new Integer({ valueHex: stringToArrayBuffer(fromBase64(json.qi, true, true)) });
		else
			throw new Error("Absent mandatory parameter \"qi\"");

		if("oth" in json)
			this.otherPrimeInfos = Array.from(json.oth, element => new OtherPrimeInfo({ json: element }));
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5208
 */
class PrivateKeyInfo
{
	//**********************************************************************************
	/**
	 * Constructor for PrivateKeyInfo class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {number}
		 * @description version
		 */
		this.version = getParametersValue(parameters, "version", PrivateKeyInfo.defaultValues("version"));
		/**
		 * @type {AlgorithmIdentifier}
		 * @description privateKeyAlgorithm
		 */
		this.privateKeyAlgorithm = getParametersValue(parameters, "privateKeyAlgorithm", PrivateKeyInfo.defaultValues("privateKeyAlgorithm"));
		/**
		 * @type {OctetString}
		 * @description privateKey
		 */
		this.privateKey = getParametersValue(parameters, "privateKey", PrivateKeyInfo.defaultValues("privateKey"));

		if("attributes" in parameters)
			/**
			 * @type {Array.<Attribute>}
			 * @description attributes
			 */
			this.attributes = getParametersValue(parameters, "attributes", PrivateKeyInfo.defaultValues("attributes"));

		if("parsedKey" in parameters)
			/**
			 * @type {ECPrivateKey|RSAPrivateKey}
			 * @description Parsed public key value
			 */
			this.parsedKey = getParametersValue(parameters, "parsedKey", PrivateKeyInfo.defaultValues("parsedKey"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
		//region If input argument array contains "json" for this object
		if("json" in parameters)
			this.fromJSON(parameters.json);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "version":
				return 0;
			case "privateKeyAlgorithm":
				return new AlgorithmIdentifier();
			case "privateKey":
				return new OctetString();
			case "attributes":
				return [];
			case "parsedKey":
				return {};
			default:
				throw new Error(`Invalid member name for PrivateKeyInfo class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//PrivateKeyInfo ::= SEQUENCE {
		//    version Version,
		//    privateKeyAlgorithm AlgorithmIdentifier {{PrivateKeyAlgorithms}},
		//    privateKey PrivateKey,
		//    attributes [0] Attributes OPTIONAL }
		//
		//Version ::= INTEGER {v1(0)} (v1,...)
		//
		//PrivateKey ::= OCTET STRING
		//
		//Attributes ::= SET OF Attribute

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [version]
		 * @property {string} [privateKeyAlgorithm]
		 * @property {string} [privateKey]
		 * @property {string} [attributes]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Integer({ name: (names.version || "") }),
				AlgorithmIdentifier.schema(names.privateKeyAlgorithm || {}),
				new OctetString({ name: (names.privateKey || "") }),
				new Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [
						new Repeated({
							name: (names.attributes || ""),
							value: Attribute.schema()
						})
					]
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			PrivateKeyInfo.schema({
				names: {
					version: "version",
					privateKeyAlgorithm: {
						names: {
							blockName: "privateKeyAlgorithm"
						}
					},
					privateKey: "privateKey",
					attributes: "attributes"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for PKCS8");
		//endregion

		//region Get internal properties from parsed schema
		this.version = asn1.result.version.valueBlock.valueDec;
		this.privateKeyAlgorithm = new AlgorithmIdentifier({ schema: asn1.result.privateKeyAlgorithm });
		this.privateKey = asn1.result.privateKey;

		if("attributes" in asn1.result)
			this.attributes = Array.from(asn1.result.attributes, element => new Attribute({ schema: element }));

		switch(this.privateKeyAlgorithm.algorithmId)
		{
			case "1.2.840.113549.1.1.1": // RSA
				{
					const privateKeyASN1 = fromBER(this.privateKey.valueBlock.valueHex);
					if(privateKeyASN1.offset !== (-1))
						this.parsedKey = new RSAPrivateKey({ schema: privateKeyASN1.result });
				}
				break;
			case "1.2.840.10045.2.1": // ECDSA
				if("algorithmParams" in this.privateKeyAlgorithm)
				{
					if(this.privateKeyAlgorithm.algorithmParams instanceof ObjectIdentifier)
					{
						const privateKeyASN1 = fromBER(this.privateKey.valueBlock.valueHex);
						if(privateKeyASN1.offset !== (-1))
						{
							this.parsedKey = new ECPrivateKey({
								namedCurve: this.privateKeyAlgorithm.algorithmParams.valueBlock.toString(),
								schema: privateKeyASN1.result
							});
						}
					}
				}
				break;
			default:
		}
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Create array for output sequence
		const outputArray = [
			new Integer({ value: this.version }),
			this.privateKeyAlgorithm.toSchema(),
			this.privateKey
		];

		if("attributes" in this)
		{
			outputArray.push(new Constructed({
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 0 // [0]
				},
				value: Array.from(this.attributes, element => element.toSchema())
			}));
		}
		//endregion
		
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: outputArray
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		//region Return common value in case we do not have enough info fo making JWK
		if(("parsedKey" in this) === false)
		{
			const object = {
				version: this.version,
				privateKeyAlgorithm: this.privateKeyAlgorithm.toJSON(),
				privateKey: this.privateKey.toJSON()
			};

			if("attributes" in this)
				object.attributes = Array.from(this.attributes, element => element.toJSON());

			return object;
		}
		//endregion

		//region Making JWK
		const jwk = {};

		switch(this.privateKeyAlgorithm.algorithmId)
		{
			case "1.2.840.10045.2.1": // ECDSA
				jwk.kty = "EC";
				break;
			case "1.2.840.113549.1.1.1": // RSA
				jwk.kty = "RSA";
				break;
			default:
		}

		const publicKeyJWK = this.parsedKey.toJSON();

		for(const key of Object.keys(publicKeyJWK))
			jwk[key] = publicKeyJWK[key];

		return jwk;
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert JSON value into current object
	 * @param {Object} json
	 */
	fromJSON(json)
	{
		if("kty" in json)
		{
			switch(json.kty.toUpperCase())
			{
				case "EC":
					this.parsedKey = new ECPrivateKey({ json });

					this.privateKeyAlgorithm = new AlgorithmIdentifier({
						algorithmId: "1.2.840.10045.2.1",
						algorithmParams: new ObjectIdentifier({ value: this.parsedKey.namedCurve })
					});
					break;
				case "RSA":
					this.parsedKey = new RSAPrivateKey({ json });

					this.privateKeyAlgorithm = new AlgorithmIdentifier({
						algorithmId: "1.2.840.113549.1.1.1",
						algorithmParams: new Null()
					});
					break;
				default:
					throw new Error(`Invalid value for "kty" parameter: ${json.kty}`);
			}

			this.privateKey = new OctetString({ valueHex: this.parsedKey.toSchema().toBER(false) });
		}
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5652
 */
class EncryptedContentInfo
{
	//**********************************************************************************
	/**
	 * Constructor for EncryptedContentInfo class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {string}
		 * @description contentType
		 */
		this.contentType = getParametersValue(parameters, "contentType", EncryptedContentInfo.defaultValues("contentType"));
		/**
		 * @type {AlgorithmIdentifier}
		 * @description contentEncryptionAlgorithm
		 */
		this.contentEncryptionAlgorithm = getParametersValue(parameters, "contentEncryptionAlgorithm", EncryptedContentInfo.defaultValues("contentEncryptionAlgorithm"));

		if("encryptedContent" in parameters)
		{
			/**
			 * @type {OctetString}
			 * @description encryptedContent (!!!) could be contructive or primitive value (!!!)
			 */
			this.encryptedContent = parameters.encryptedContent;
			
			if((this.encryptedContent.idBlock.tagClass === 1) &&
				(this.encryptedContent.idBlock.tagNumber === 4))
			{
				//region Divide OCTETSTRING value down to small pieces
				if(this.encryptedContent.idBlock.isConstructed === false)
				{
					const constrString = new OctetString({
						idBlock: { isConstructed: true },
						isConstructed: true
					});
					
					let offset = 0;
					let length = this.encryptedContent.valueBlock.valueHex.byteLength;
					
					while(length > 0)
					{
						const pieceView = new Uint8Array(this.encryptedContent.valueBlock.valueHex, offset, ((offset + 1024) > this.encryptedContent.valueBlock.valueHex.byteLength) ? (this.encryptedContent.valueBlock.valueHex.byteLength - offset) : 1024);
						const _array = new ArrayBuffer(pieceView.length);
						const _view = new Uint8Array(_array);
						
						for(let i = 0; i < _view.length; i++)
							_view[i] = pieceView[i];
						
						constrString.valueBlock.value.push(new OctetString({ valueHex: _array }));
						
						length -= pieceView.length;
						offset += pieceView.length;
					}
					
					this.encryptedContent = constrString;
				}
				//endregion
			}
		}
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "contentType":
				return "";
			case "contentEncryptionAlgorithm":
				return new AlgorithmIdentifier();
			case "encryptedContent":
				return new OctetString();
			default:
				throw new Error(`Invalid member name for EncryptedContentInfo class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Compare values with default values for all class members
	 * @param {string} memberName String name for a class member
	 * @param {*} memberValue Value to compare with default value
	 */
	static compareWithDefault(memberName, memberValue)
	{
		switch(memberName)
		{
			case "contentType":
				return (memberValue === "");
			case "contentEncryptionAlgorithm":
				return ((memberValue.algorithmId === "") && (("algorithmParams" in memberValue) === false));
			case "encryptedContent":
				return (memberValue.isEqual(EncryptedContentInfo.defaultValues(memberName)));
			default:
				throw new Error(`Invalid member name for EncryptedContentInfo class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//EncryptedContentInfo ::= SEQUENCE {
		//    contentType ContentType,
		//    contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
		//    encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
		//
		// Comment: Strange, but modern crypto engines create "encryptedContent" as "[0] EXPLICIT EncryptedContent"
		//
		//EncryptedContent ::= OCTET STRING

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [contentType]
		 * @property {string} [contentEncryptionAlgorithm]
		 * @property {string} [encryptedContent]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new ObjectIdentifier({ name: (names.contentType || "") }),
				AlgorithmIdentifier.schema(names.contentEncryptionAlgorithm || {}),
				// The CHOICE we need because "EncryptedContent" could have either "constructive"
				// or "primitive" form of encoding and we need to handle both variants
				new Choice({
					value: [
						new Constructed({
							name: (names.encryptedContent || ""),
							idBlock: {
								tagClass: 3, // CONTEXT-SPECIFIC
								tagNumber: 0 // [0]
							},
							value: [
								new Repeated({
									value: new OctetString()
								})
							]
						}),
						new Primitive({
							name: (names.encryptedContent || ""),
							idBlock: {
								tagClass: 3, // CONTEXT-SPECIFIC
								tagNumber: 0 // [0]
							}
						})
					]
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			EncryptedContentInfo.schema({
				names: {
					contentType: "contentType",
					contentEncryptionAlgorithm: {
						names: {
							blockName: "contentEncryptionAlgorithm"
						}
					},
					encryptedContent: "encryptedContent"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for EncryptedContentInfo");
		//endregion

		//region Get internal properties from parsed schema
		this.contentType = asn1.result.contentType.valueBlock.toString();
		this.contentEncryptionAlgorithm = new AlgorithmIdentifier({ schema: asn1.result.contentEncryptionAlgorithm });

		if("encryptedContent" in asn1.result)
		{
			this.encryptedContent = asn1.result.encryptedContent;

			this.encryptedContent.idBlock.tagClass = 1; // UNIVERSAL
			this.encryptedContent.idBlock.tagNumber = 4; // OCTETSTRING (!!!) The value still has instance of "in_window.org.pkijs.asn1.ASN1_CONSTRUCTED / ASN1_PRIMITIVE"
		}
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Create array for output sequence
		const sequenceLengthBlock = {
			isIndefiniteForm: false
		};

		const outputArray = [];

		outputArray.push(new ObjectIdentifier({ value: this.contentType }));
		outputArray.push(this.contentEncryptionAlgorithm.toSchema());

		if("encryptedContent" in this)
		{
			sequenceLengthBlock.isIndefiniteForm = this.encryptedContent.idBlock.isConstructed;

			const encryptedValue = this.encryptedContent;

			encryptedValue.idBlock.tagClass = 3; // CONTEXT-SPECIFIC
			encryptedValue.idBlock.tagNumber = 0; // [0]

			encryptedValue.lenBlock.isIndefiniteForm = this.encryptedContent.idBlock.isConstructed;

			outputArray.push(encryptedValue);
		}
		//endregion

		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			lenBlock: sequenceLengthBlock,
			value: outputArray
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		const _object = {
			contentType: this.contentType,
			contentEncryptionAlgorithm: this.contentEncryptionAlgorithm.toJSON()
		};

		if("encryptedContent" in this)
			_object.encryptedContent = this.encryptedContent.toJSON();

		return _object;
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC4055
 */
class RSASSAPSSParams
{
	//**********************************************************************************
	/**
	 * Constructor for RSASSAPSSParams class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {AlgorithmIdentifier}
		 * @description Algorithms of hashing (DEFAULT sha1)
		 */
		this.hashAlgorithm = getParametersValue(parameters, "hashAlgorithm", RSASSAPSSParams.defaultValues("hashAlgorithm"));
		/**
		 * @type {AlgorithmIdentifier}
		 * @description Algorithm of "mask generaion function (MGF)" (DEFAULT mgf1SHA1)
		 */
		this.maskGenAlgorithm = getParametersValue(parameters, "maskGenAlgorithm", RSASSAPSSParams.defaultValues("maskGenAlgorithm"));
		/**
		 * @type {number}
		 * @description Salt length (DEFAULT 20)
		 */
		this.saltLength = getParametersValue(parameters, "saltLength", RSASSAPSSParams.defaultValues("saltLength"));
		/**
		 * @type {number}
		 * @description (DEFAULT 1)
		 */
		this.trailerField = getParametersValue(parameters, "trailerField", RSASSAPSSParams.defaultValues("trailerField"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "hashAlgorithm":
				return new AlgorithmIdentifier({
					algorithmId: "1.3.14.3.2.26", // SHA-1
					algorithmParams: new Null()
				});
			case "maskGenAlgorithm":
				return new AlgorithmIdentifier({
					algorithmId: "1.2.840.113549.1.1.8", // MGF1
					algorithmParams: (new AlgorithmIdentifier({
						algorithmId: "1.3.14.3.2.26", // SHA-1
						algorithmParams: new Null()
					})).toSchema()
				});
			case "saltLength":
				return 20;
			case "trailerField":
				return 1;
			default:
				throw new Error(`Invalid member name for RSASSAPSSParams class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//RSASSA-PSS-params  ::=  Sequence  {
		//    hashAlgorithm      [0] HashAlgorithm DEFAULT sha1Identifier,
		//    maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT mgf1SHA1Identifier,
		//    saltLength         [2] Integer DEFAULT 20,
		//    trailerField       [3] Integer DEFAULT 1  }

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [hashAlgorithm]
		 * @property {string} [maskGenAlgorithm]
		 * @property {string} [saltLength]
		 * @property {string} [trailerField]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					optional: true,
					value: [AlgorithmIdentifier.schema(names.hashAlgorithm || {})]
				}),
				new Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					optional: true,
					value: [AlgorithmIdentifier.schema(names.maskGenAlgorithm || {})]
				}),
				new Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 2 // [2]
					},
					optional: true,
					value: [new Integer({ name: (names.saltLength || "") })]
				}),
				new Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 3 // [3]
					},
					optional: true,
					value: [new Integer({ name: (names.trailerField || "") })]
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			RSASSAPSSParams.schema({
				names: {
					hashAlgorithm: {
						names: {
							blockName: "hashAlgorithm"
						}
					},
					maskGenAlgorithm: {
						names: {
							blockName: "maskGenAlgorithm"
						}
					},
					saltLength: "saltLength",
					trailerField: "trailerField"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for RSASSA_PSS_params");
		//endregion

		//region Get internal properties from parsed schema
		if("hashAlgorithm" in asn1.result)
			this.hashAlgorithm = new AlgorithmIdentifier({ schema: asn1.result.hashAlgorithm });

		if("maskGenAlgorithm" in asn1.result)
			this.maskGenAlgorithm = new AlgorithmIdentifier({ schema: asn1.result.maskGenAlgorithm });

		if("saltLength" in asn1.result)
			this.saltLength = asn1.result.saltLength.valueBlock.valueDec;

		if("trailerField" in asn1.result)
			this.trailerField = asn1.result.trailerField.valueBlock.valueDec;
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Create array for output sequence
		const outputArray = [];
		
		if(!this.hashAlgorithm.isEqual(RSASSAPSSParams.defaultValues("hashAlgorithm")))
		{
			outputArray.push(new Constructed({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 0 // [0]
				},
				value: [this.hashAlgorithm.toSchema()]
			}));
		}
		
		if(!this.maskGenAlgorithm.isEqual(RSASSAPSSParams.defaultValues("maskGenAlgorithm")))
		{
			outputArray.push(new Constructed({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 1 // [1]
				},
				value: [this.maskGenAlgorithm.toSchema()]
			}));
		}
		
		if(this.saltLength !== RSASSAPSSParams.defaultValues("saltLength"))
		{
			outputArray.push(new Constructed({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 2 // [2]
				},
				value: [new Integer({ value: this.saltLength })]
			}));
		}
		
		if(this.trailerField !== RSASSAPSSParams.defaultValues("trailerField"))
		{
			outputArray.push(new Constructed({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 3 // [3]
				},
				value: [new Integer({ value: this.trailerField })]
			}));
		}
		//endregion
		
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: outputArray
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		const object = {};

		if(!this.hashAlgorithm.isEqual(RSASSAPSSParams.defaultValues("hashAlgorithm")))
			object.hashAlgorithm = this.hashAlgorithm.toJSON();

		if(!this.maskGenAlgorithm.isEqual(RSASSAPSSParams.defaultValues("maskGenAlgorithm")))
			object.maskGenAlgorithm = this.maskGenAlgorithm.toJSON();

		if(this.saltLength !== RSASSAPSSParams.defaultValues("saltLength"))
			object.saltLength = this.saltLength;

		if(this.trailerField !== RSASSAPSSParams.defaultValues("trailerField"))
			object.trailerField = this.trailerField;

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC2898
 */
class PBKDF2Params
{
	//**********************************************************************************
	/**
	 * Constructor for PBKDF2Params class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Object}
		 * @description salt
		 */
		this.salt = getParametersValue(parameters, "salt", PBKDF2Params.defaultValues("salt"));
		/**
		 * @type {number}
		 * @description iterationCount
		 */
		this.iterationCount = getParametersValue(parameters, "iterationCount", PBKDF2Params.defaultValues("iterationCount"));
		
		if("keyLength" in parameters)
			/**
			 * @type {number}
			 * @description keyLength
			 */
			this.keyLength = getParametersValue(parameters, "keyLength", PBKDF2Params.defaultValues("keyLength"));
		
		if("prf" in parameters)
			/**
			 * @type {AlgorithmIdentifier}
			 * @description prf
			 */
			this.prf = getParametersValue(parameters, "prf", PBKDF2Params.defaultValues("prf"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "salt":
				return {};
			case "iterationCount":
				return (-1);
			case "keyLength":
				return 0;
			case "prf":
				return new AlgorithmIdentifier({
					algorithmId: "1.3.14.3.2.26", // SHA-1
					algorithmParams: new Null()
				});
			default:
				throw new Error(`Invalid member name for PBKDF2Params class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//PBKDF2-params ::= SEQUENCE {
		//    salt CHOICE {
		//        specified OCTET STRING,
		//        otherSource AlgorithmIdentifier },
		//  iterationCount INTEGER (1..MAX),
		//  keyLength INTEGER (1..MAX) OPTIONAL,
		//  prf AlgorithmIdentifier
		//    DEFAULT { algorithm hMAC-SHA1, parameters NULL } }

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [saltPrimitive]
		 * @property {string} [saltConstructed]
		 * @property {string} [iterationCount]
		 * @property {string} [keyLength]
		 * @property {string} [prf]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Choice({
					value: [
						new OctetString({ name: (names.saltPrimitive || "") }),
						AlgorithmIdentifier.schema(names.saltConstructed || {})
					]
				}),
				new Integer({ name: (names.iterationCount || "") }),
				new Integer({
					name: (names.keyLength || ""),
					optional: true
				}),
				AlgorithmIdentifier.schema(names.prf || {
					names: {
						optional: true
					}
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			PBKDF2Params.schema({
				names: {
					saltPrimitive: "salt",
					saltConstructed: {
						names: {
							blockName: "salt"
						}
					},
					iterationCount: "iterationCount",
					keyLength: "keyLength",
					prf: {
						names: {
							blockName: "prf",
							optional: true
						}
					}
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for PBKDF2_params");
		//endregion

		//region Get internal properties from parsed schema
		this.salt = asn1.result.salt;
		this.iterationCount = asn1.result.iterationCount.valueBlock.valueDec;

		if("keyLength" in asn1.result)
			this.keyLength = asn1.result.keyLength.valueBlock.valueDec;

		if("prf" in asn1.result)
			this.prf = new AlgorithmIdentifier({ schema: asn1.result.prf });
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Create array for output sequence 
		const outputArray = [];
		
		outputArray.push(this.salt);
		outputArray.push(new Integer({ value: this.iterationCount }));
		
		if("keyLength" in this)
		{
			if(PBKDF2Params.defaultValues("keyLength") !== this.keyLength)
				outputArray.push(new Integer({ value: this.keyLength }));
		}
		
		if("prf" in this)
		{
			if(PBKDF2Params.defaultValues("prf").isEqual(this.prf) === false)
				outputArray.push(this.prf.toSchema());
		}
		//endregion 
		
		//region Construct and return new ASN.1 schema for this object 
		return (new Sequence({
			value: outputArray
		}));
		//endregion 
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		const _object = {
			salt: this.salt.toJSON(),
			iterationCount: this.iterationCount
		};
		
		if("keyLength" in this)
		{
			if(PBKDF2Params.defaultValues("keyLength") !== this.keyLength)
				_object.keyLength = this.keyLength;
		}
		
		if("prf" in this)
		{
			if(PBKDF2Params.defaultValues("prf").isEqual(this.prf) === false)
				_object.prf = this.prf.toJSON();
		}

		return _object;
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC2898
 */
class PBES2Params
{
	//**********************************************************************************
	/**
	 * Constructor for PBES2Params class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {AlgorithmIdentifier}
		 * @description keyDerivationFunc
		 */
		this.keyDerivationFunc = getParametersValue(parameters, "keyDerivationFunc", PBES2Params.defaultValues("keyDerivationFunc"));
		/**
		 * @type {AlgorithmIdentifier}
		 * @description encryptionScheme
		 */
		this.encryptionScheme = getParametersValue(parameters, "encryptionScheme", PBES2Params.defaultValues("encryptionScheme"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "keyDerivationFunc":
				return new AlgorithmIdentifier();
			case "encryptionScheme":
				return new AlgorithmIdentifier();
			default:
				throw new Error(`Invalid member name for PBES2Params class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//PBES2-params ::= SEQUENCE {
		//    keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
		//    encryptionScheme AlgorithmIdentifier {{PBES2-Encs}} }

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [keyDerivationFunc]
		 * @property {string} [encryptionScheme]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				AlgorithmIdentifier.schema(names.keyDerivationFunc || {}),
				AlgorithmIdentifier.schema(names.encryptionScheme || {})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			PBES2Params.schema({
				names: {
					keyDerivationFunc: {
						names: {
							blockName: "keyDerivationFunc"
						}
					},
					encryptionScheme: {
						names: {
							blockName: "encryptionScheme"
						}
					}
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for PBES2_params");
		//endregion

		//region Get internal properties from parsed schema
		this.keyDerivationFunc = new AlgorithmIdentifier({ schema: asn1.result.keyDerivationFunc });
		this.encryptionScheme = new AlgorithmIdentifier({ schema: asn1.result.encryptionScheme });
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: [
				this.keyDerivationFunc.toSchema(),
				this.encryptionScheme.toSchema()
			]
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		return {
			keyDerivationFunc: this.keyDerivationFunc.toJSON(),
			encryptionScheme: this.encryptionScheme.toJSON()
		};
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Making MAC key using algorithm described in B.2 of PKCS#12 standard.
 */
function makePKCS12B2Key(cryptoEngine, hashAlgorithm, keyLength, password, salt, iterationCount)
{
	//region Initial variables
	let u;
	let v;
	
	const result = [];
	//endregion
	
	//region Get "u" and "v" values
	switch(hashAlgorithm.toUpperCase())
	{
		case "SHA-1":
			u = 20; // 160
			v = 64; // 512
			break;
		case "SHA-256":
			u = 32; // 256
			v = 64; // 512
			break;
		case "SHA-384":
			u = 48; // 384
			v = 128; // 1024
			break;
		case "SHA-512":
			u = 64; // 512
			v = 128; // 1024
			break;
		default:
			throw new Error("Unsupported hashing algorithm");
	}
	//endregion
	
	//region Main algorithm making key
	//region Transform password to UTF-8 like string
	const passwordViewInitial = new Uint8Array(password);
	
	const passwordTransformed = new ArrayBuffer((password.byteLength * 2) + 2);
	const passwordTransformedView = new Uint8Array(passwordTransformed);
	
	for(let i = 0; i < passwordViewInitial.length; i++)
	{
		passwordTransformedView[i * 2] = 0x00;
		passwordTransformedView[i * 2 + 1] = passwordViewInitial[i];
	}
	
	passwordTransformedView[passwordTransformedView.length - 2] = 0x00;
	passwordTransformedView[passwordTransformedView.length - 1] = 0x00;
	
	password = passwordTransformed.slice(0);
	//endregion
	
	//region Construct a string D (the "diversifier") by concatenating v/8 copies of ID
	const D = new ArrayBuffer(v);
	const dView = new Uint8Array(D);
	
	for(let i = 0; i < D.byteLength; i++)
		dView[i] = 3; // The ID value equal to "3" for MACing (see B.3 of standard)
	//endregion
	
	//region Concatenate copies of the salt together to create a string S of length v * ceil(s / v) bytes (the final copy of the salt may be trunacted to create S)
	const saltLength = salt.byteLength;
	
	const sLen = v * Math.ceil(saltLength / v);
	const S = new ArrayBuffer(sLen);
	const sView = new Uint8Array(S);
	
	const saltView = new Uint8Array(salt);
	
	for(let i = 0; i < sLen; i++)
		sView[i] = saltView[i % saltLength];
	//endregion
	
	//region Concatenate copies of the password together to create a string P of length v * ceil(p / v) bytes (the final copy of the password may be truncated to create P)
	const passwordLength = password.byteLength;
	
	const pLen = v * Math.ceil(passwordLength / v);
	const P = new ArrayBuffer(pLen);
	const pView = new Uint8Array(P);
	
	const passwordView = new Uint8Array(password);
	
	for(let i = 0; i < pLen; i++)
		pView[i] = passwordView[i % passwordLength];
	//endregion
	
	//region Set I=S||P to be the concatenation of S and P
	const sPlusPLength = S.byteLength + P.byteLength;
	
	let I = new ArrayBuffer(sPlusPLength);
	let iView = new Uint8Array(I);
	
	iView.set(sView);
	iView.set(pView, sView.length);
	//endregion
	
	//region Set c=ceil(n / u)
	const c = Math.ceil((keyLength >> 3) / u);
	//endregion
	
	//region Initial variables
	let internalSequence = Promise.resolve(I);
	//endregion
	
	//region For i=1, 2, ..., c, do the following:
	for(let i = 0; i <= c; i++)
	{
		internalSequence = internalSequence.then(_I =>
		{
			//region Create contecanetion of D and I
			const dAndI = new ArrayBuffer(D.byteLength + _I.byteLength);
			const dAndIView = new Uint8Array(dAndI);
			
			dAndIView.set(dView);
			dAndIView.set(iView, dView.length);
			//endregion
			
			return dAndI;
		});
		
		//region Make "iterationCount" rounds of hashing
		for(let j = 0; j < iterationCount; j++)
			internalSequence = internalSequence.then(roundBuffer => cryptoEngine.digest({ name: hashAlgorithm }, new Uint8Array(roundBuffer)));
		//endregion
		
		internalSequence = internalSequence.then(roundBuffer =>
		{
			//region Concatenate copies of Ai to create a string B of length v bits (the final copy of Ai may be truncated to create B)
			const B = new ArrayBuffer(v);
			const bView = new Uint8Array(B);
			
			for(let j = 0; j < B.byteLength; j++)
				bView[j] = roundBuffer[j % roundBuffer.length];
			//endregion
			
			//region Make new I value
			const k = Math.ceil(saltLength / v) + Math.ceil(passwordLength / v);
			const iRound = [];
			
			let sliceStart = 0;
			let sliceLength = v;
			
			for(let j = 0; j < k; j++)
			{
				const chunk = Array.from(new Uint8Array(I.slice(sliceStart, sliceStart + sliceLength)));
				sliceStart += v;
				if((sliceStart + v) > I.byteLength)
					sliceLength = I.byteLength - sliceStart;
				
				let x = 0x1ff;
				
				for(let l = (B.byteLength - 1); l >= 0; l--)
				{
					x >>= 8;
					x += bView[l] + chunk[l];
					chunk[l] = (x & 0xff);
				}
				
				iRound.push(...chunk);
			}
			
			I = new ArrayBuffer(iRound.length);
			iView = new Uint8Array(I);
			
			iView.set(iRound);
			//endregion
			
			result.push(...(new Uint8Array(roundBuffer)));
			
			return I;
		});
	}
	//endregion
	
	//region Initialize final key
	internalSequence = internalSequence.then(() =>
	{
		const resultBuffer = new ArrayBuffer(keyLength >> 3);
		const resultView = new Uint8Array(resultBuffer);
		
		resultView.set((new Uint8Array(result)).slice(0, keyLength >> 3));
		
		return resultBuffer;
	});
	//endregion
	//endregion
	
	return internalSequence;
}
//**************************************************************************************
/**
 * Default cryptographic engine for Web Cryptography API
 */
class CryptoEngine
{
	//**********************************************************************************
	/**
	 * Constructor for CryptoEngine class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Object}
		 * @description Usually here we are expecting "window.crypto" or an equivalent from custom "crypto engine"
		 */
		this.crypto = getParametersValue(parameters, "crypto", {});
		/**
		 * @type {Object}
		 * @description Usually here we are expecting "window.crypto.subtle" or an equivalent from custom "crypto engine"
		 */
		this.subtle = getParametersValue(parameters, "subtle", {});
		/**
		 * @type {string}
		 * @description Name of the "crypto engine"
		 */
		this.name = getParametersValue(parameters, "name", "");
		//endregion
	}
	//**********************************************************************************
	/**
	 * Import WebCrypto keys from different formats
	 * @param {string} format
	 * @param {ArrayBuffer|Uint8Array} keyData
	 * @param {Object} algorithm
	 * @param {boolean} extractable
	 * @param {Array} keyUsages
	 * @returns {Promise}
	 */
	importKey(format, keyData, algorithm, extractable, keyUsages)
	{
		//region Initial variables
		let jwk = {};
		//endregion
		
		//region Change "keyData" type if needed
		if(keyData instanceof Uint8Array)
			keyData = keyData.buffer;
		//endregion
		
		switch(format.toLowerCase())
		{
			case "raw":
				return this.subtle.importKey("raw", keyData, algorithm, extractable, keyUsages);
			case "spki":
				{
					const asn1 = fromBER(keyData);
					if(asn1.offset === (-1))
						return Promise.reject("Incorrect keyData");

					const publicKeyInfo = new PublicKeyInfo();
					try
					{
						publicKeyInfo.fromSchema(asn1.result);
					}
					catch(ex)
					{
						return Promise.reject("Incorrect keyData");
					}


					// noinspection FallThroughInSwitchStatementJS
					switch(algorithm.name.toUpperCase())
					{
						case "RSA-PSS":
							{
								//region Get information about used hash function
								switch(algorithm.hash.name.toUpperCase())
								{
									case "SHA-1":
										jwk.alg = "PS1";
										break;
									case "SHA-256":
										jwk.alg = "PS256";
										break;
									case "SHA-384":
										jwk.alg = "PS384";
										break;
									case "SHA-512":
										jwk.alg = "PS512";
										break;
									default:
										return Promise.reject(`Incorrect hash algorithm: ${algorithm.hash.name.toUpperCase()}`);
								}
								//endregion
							}
							// break omitted
						case "RSASSA-PKCS1-V1_5":
							{
								keyUsages = ["verify"]; // Override existing keyUsages value since the key is a public key

								jwk.kty = "RSA";
								jwk.ext = extractable;
								jwk.key_ops = keyUsages;

								if(publicKeyInfo.algorithm.algorithmId !== "1.2.840.113549.1.1.1")
									return Promise.reject(`Incorrect public key algorithm: ${publicKeyInfo.algorithm.algorithmId}`);

								//region Get information about used hash function
								if(("alg" in jwk) === false)
								{
									switch(algorithm.hash.name.toUpperCase())
									{
										case "SHA-1":
											jwk.alg = "RS1";
											break;
										case "SHA-256":
											jwk.alg = "RS256";
											break;
										case "SHA-384":
											jwk.alg = "RS384";
											break;
										case "SHA-512":
											jwk.alg = "RS512";
											break;
										default:
											return Promise.reject(`Incorrect public key algorithm: ${publicKeyInfo.algorithm.algorithmId}`);
									}
								}
								//endregion

								//region Create RSA Public Key elements
								const publicKeyJSON = publicKeyInfo.toJSON();

								for(const key of Object.keys(publicKeyJSON))
									jwk[key] = publicKeyJSON[key];
								//endregion
							}
							break;
						case "ECDSA":
							keyUsages = ["verify"]; // Override existing keyUsages value since the key is a public key
							// break omitted
						case "ECDH":
							{
								//region Initial variables
								jwk = {
									kty: "EC",
									ext: extractable,
									key_ops: keyUsages
								};
								//endregion

								//region Get information about algorithm
								if(publicKeyInfo.algorithm.algorithmId !== "1.2.840.10045.2.1")
									return Promise.reject(`Incorrect public key algorithm: ${publicKeyInfo.algorithm.algorithmId}`);
								//endregion

								//region Create ECDSA Public Key elements
								const publicKeyJSON = publicKeyInfo.toJSON();

								for(const key of Object.keys(publicKeyJSON))
									jwk[key] = publicKeyJSON[key];
								//endregion
							}
							break;
						case "RSA-OAEP":
							{
								jwk.kty = "RSA";
								jwk.ext = extractable;
								jwk.key_ops = keyUsages;
								
								if(this.name.toLowerCase() === "safari")
									jwk.alg = "RSA-OAEP";
								else
								{
									switch(algorithm.hash.name.toUpperCase())
									{
										case "SHA-1":
											jwk.alg = "RSA-OAEP-1";
											break;
										case "SHA-256":
											jwk.alg = "RSA-OAEP-256";
											break;
										case "SHA-384":
											jwk.alg = "RSA-OAEP-384";
											break;
										case "SHA-512":
											jwk.alg = "RSA-OAEP-512";
											break;
										default:
											return Promise.reject(`Incorrect public key algorithm: ${publicKeyInfo.algorithm.algorithmId}`);
									}
								}
								
								//region Create ECDSA Public Key elements
								const publicKeyJSON = publicKeyInfo.toJSON();
								
								for(const key of Object.keys(publicKeyJSON))
									jwk[key] = publicKeyJSON[key];
								//endregion
							}
							break;
						default:
							return Promise.reject(`Incorrect algorithm name: ${algorithm.name.toUpperCase()}`);
					}
				}
				break;
			case "pkcs8":
				{
					const privateKeyInfo = new PrivateKeyInfo();

					//region Parse "PrivateKeyInfo" object
					const asn1 = fromBER(keyData);
					if(asn1.offset === (-1))
						return Promise.reject("Incorrect keyData");

					try
					{
						privateKeyInfo.fromSchema(asn1.result);
					}
					catch(ex)
					{
						return Promise.reject("Incorrect keyData");
					}
					
					if(("parsedKey" in privateKeyInfo) === false)
						return Promise.reject("Incorrect keyData");
					//endregion

					// noinspection FallThroughInSwitchStatementJS
					// noinspection FallThroughInSwitchStatementJS
					switch(algorithm.name.toUpperCase())
					{
						case "RSA-PSS":
							{
								//region Get information about used hash function
								switch(algorithm.hash.name.toUpperCase())
								{
									case "SHA-1":
										jwk.alg = "PS1";
										break;
									case "SHA-256":
										jwk.alg = "PS256";
										break;
									case "SHA-384":
										jwk.alg = "PS384";
										break;
									case "SHA-512":
										jwk.alg = "PS512";
										break;
									default:
										return Promise.reject(`Incorrect hash algorithm: ${algorithm.hash.name.toUpperCase()}`);
								}
								//endregion
							}
							// break omitted
						case "RSASSA-PKCS1-V1_5":
							{
								keyUsages = ["sign"]; // Override existing keyUsages value since the key is a private key

								jwk.kty = "RSA";
								jwk.ext = extractable;
								jwk.key_ops = keyUsages;

								//region Get information about used hash function
								if(privateKeyInfo.privateKeyAlgorithm.algorithmId !== "1.2.840.113549.1.1.1")
									return Promise.reject(`Incorrect private key algorithm: ${privateKeyInfo.privateKeyAlgorithm.algorithmId}`);
								//endregion

								//region Get information about used hash function
								if(("alg" in jwk) === false)
								{
									switch(algorithm.hash.name.toUpperCase())
									{
										case "SHA-1":
											jwk.alg = "RS1";
											break;
										case "SHA-256":
											jwk.alg = "RS256";
											break;
										case "SHA-384":
											jwk.alg = "RS384";
											break;
										case "SHA-512":
											jwk.alg = "RS512";
											break;
										default:
											return Promise.reject(`Incorrect hash algorithm: ${algorithm.hash.name.toUpperCase()}`);
									}
								}
								//endregion

								//region Create RSA Private Key elements
								const privateKeyJSON = privateKeyInfo.toJSON();

								for(const key of Object.keys(privateKeyJSON))
									jwk[key] = privateKeyJSON[key];
								//endregion
							}
							break;
						case "ECDSA":
							keyUsages = ["sign"]; // Override existing keyUsages value since the key is a private key
							// break omitted
						case "ECDH":
							{
								//region Initial variables
								jwk = {
									kty: "EC",
									ext: extractable,
									key_ops: keyUsages
								};
								//endregion

								//region Get information about used hash function
								if(privateKeyInfo.privateKeyAlgorithm.algorithmId !== "1.2.840.10045.2.1")
									return Promise.reject(`Incorrect algorithm: ${privateKeyInfo.privateKeyAlgorithm.algorithmId}`);
								//endregion

								//region Create ECDSA Private Key elements
								const privateKeyJSON = privateKeyInfo.toJSON();

								for(const key of Object.keys(privateKeyJSON))
									jwk[key] = privateKeyJSON[key];
								//endregion
							}
							break;
						case "RSA-OAEP":
							{
								jwk.kty = "RSA";
								jwk.ext = extractable;
								jwk.key_ops = keyUsages;
								
								//region Get information about used hash function
								if(this.name.toLowerCase() === "safari")
									jwk.alg = "RSA-OAEP";
								else
								{
									switch(algorithm.hash.name.toUpperCase())
									{
										case "SHA-1":
											jwk.alg = "RSA-OAEP-1";
											break;
										case "SHA-256":
											jwk.alg = "RSA-OAEP-256";
											break;
										case "SHA-384":
											jwk.alg = "RSA-OAEP-384";
											break;
										case "SHA-512":
											jwk.alg = "RSA-OAEP-512";
											break;
										default:
											return Promise.reject(`Incorrect hash algorithm: ${algorithm.hash.name.toUpperCase()}`);
									}
								}
								//endregion
								
								//region Create RSA Private Key elements
								const privateKeyJSON = privateKeyInfo.toJSON();
								
								for(const key of Object.keys(privateKeyJSON))
									jwk[key] = privateKeyJSON[key];
								//endregion
							}
							break;
						default:
							return Promise.reject(`Incorrect algorithm name: ${algorithm.name.toUpperCase()}`);
					}
				}
				break;
			case "jwk":
				jwk = keyData;
				break;
			default:
				return Promise.reject(`Incorrect format: ${format}`);
		}
		
		//region Special case for Safari browser (since its acting not as WebCrypto standard describes)
		if(this.name.toLowerCase() === "safari")
		{
			// Try to use both ways - import using ArrayBuffer and pure JWK (for Safari Technology Preview)
			return Promise.resolve().then(() => this.subtle.importKey("jwk", stringToArrayBuffer(JSON.stringify(jwk)), algorithm, extractable, keyUsages))
				.then(result => result, () => this.subtle.importKey("jwk", jwk, algorithm, extractable, keyUsages));
		}
		//endregion
		
		return this.subtle.importKey("jwk", jwk, algorithm, extractable, keyUsages);
	}
	//**********************************************************************************
	/**
	 * Export WebCrypto keys to different formats
	 * @param {string} format
	 * @param {Object} key
	 * @returns {Promise}
	 */
	exportKey(format, key)
	{
		let sequence = this.subtle.exportKey("jwk", key);
		
		//region Currently Safari returns ArrayBuffer as JWK thus we need an additional transformation
		if(this.name.toLowerCase() === "safari")
		{
			sequence = sequence.then(result =>
			{
				// Some additional checks for Safari Technology Preview
				if(result instanceof ArrayBuffer)
					return JSON.parse(arrayBufferToString(result));
				
				return result;
			});
		}
		//endregion
		
		switch(format.toLowerCase())
		{
			case "raw":
				return this.subtle.exportKey("raw", key);
			case "spki":
				sequence = sequence.then(result =>
				{
					const publicKeyInfo = new PublicKeyInfo();

					try
					{
						publicKeyInfo.fromJSON(result);
					}
					catch(ex)
					{
						return Promise.reject("Incorrect key data");
					}

					return publicKeyInfo.toSchema().toBER(false);
				});
				break;
			case "pkcs8":
				sequence = sequence.then(result =>
				{
					const privateKeyInfo = new PrivateKeyInfo();

					try
					{
						privateKeyInfo.fromJSON(result);
					}
					catch(ex)
					{
						return Promise.reject("Incorrect key data");
					}

					return privateKeyInfo.toSchema().toBER(false);
				});
				break;
			case "jwk":
				break;
			default:
				return Promise.reject(`Incorrect format: ${format}`);
		}

		return sequence;
	}
	//**********************************************************************************
	/**
	 * Convert WebCrypto keys between different export formats
	 * @param {string} inputFormat
	 * @param {string} outputFormat
	 * @param {ArrayBuffer|Object} keyData
	 * @param {Object} algorithm
	 * @param {boolean} extractable
	 * @param {Array} keyUsages
	 * @returns {Promise}
	 */
	convert(inputFormat, outputFormat, keyData, algorithm, extractable, keyUsages)
	{
		switch(inputFormat.toLowerCase())
		{
			case "raw":
				switch(outputFormat.toLowerCase())
				{
					case "raw":
						return Promise.resolve(keyData);
					case "spki":
						return Promise.resolve()
							.then(() => this.importKey("raw", keyData, algorithm, extractable, keyUsages))
							.then(result => this.exportKey("spki", result));
					case "pkcs8":
						return Promise.resolve()
							.then(() => this.importKey("raw", keyData, algorithm, extractable, keyUsages))
							.then(result => this.exportKey("pkcs8", result));
					case "jwk":
						return Promise.resolve()
							.then(() => this.importKey("raw", keyData, algorithm, extractable, keyUsages))
							.then(result => this.exportKey("jwk", result));
					default:
						return Promise.reject(`Incorrect outputFormat: ${outputFormat}`);
				}
			case "spki":
				switch(outputFormat.toLowerCase())
				{
					case "raw":
						return Promise.resolve()
							.then(() => this.importKey("spki", keyData, algorithm, extractable, keyUsages))
							.then(result => this.exportKey("raw", result));
					case "spki":
						return Promise.resolve(keyData);
					case "pkcs8":
						return Promise.reject("Impossible to convert between SPKI/PKCS8");
					case "jwk":
						return Promise.resolve()
							.then(() => this.importKey("spki", keyData, algorithm, extractable, keyUsages))
							.then(result => this.exportKey("jwk", result));
					default:
						return Promise.reject(`Incorrect outputFormat: ${outputFormat}`);
				}
			case "pkcs8":
				switch(outputFormat.toLowerCase())
				{
					case "raw":
						return Promise.resolve()
							.then(() => this.importKey("pkcs8", keyData, algorithm, extractable, keyUsages))
							.then(result => this.exportKey("raw", result));
					case "spki":
						return Promise.reject("Impossible to convert between SPKI/PKCS8");
					case "pkcs8":
						return Promise.resolve(keyData);
					case "jwk":
						return Promise.resolve()
							.then(() => this.importKey("pkcs8", keyData, algorithm, extractable, keyUsages))
							.then(result => this.exportKey("jwk", result));
					default:
						return Promise.reject(`Incorrect outputFormat: ${outputFormat}`);
				}
			case "jwk":
				switch(outputFormat.toLowerCase())
				{
					case "raw":
						return Promise.resolve()
							.then(() => this.importKey("jwk", keyData, algorithm, extractable, keyUsages))
							.then(result => this.exportKey("raw", result));
					case "spki":
						return Promise.resolve()
							.then(() => this.importKey("jwk", keyData, algorithm, extractable, keyUsages))
							.then(result => this.exportKey("spki", result));
					case "pkcs8":
						return Promise.resolve()
							.then(() => this.importKey("jwk", keyData, algorithm, extractable, keyUsages))
							.then(result => this.exportKey("pkcs8", result));
					case "jwk":
						return Promise.resolve(keyData);
					default:
						return Promise.reject(`Incorrect outputFormat: ${outputFormat}`);
				}
			default:
				return Promise.reject(`Incorrect inputFormat: ${inputFormat}`);
		}
	}
	//**********************************************************************************
	/**
	 * Wrapper for standard function "encrypt"
	 * @param args
	 * @returns {Promise}
	 */
	encrypt(...args)
	{
		return this.subtle.encrypt(...args);
	}
	//**********************************************************************************
	/**
	 * Wrapper for standard function "decrypt"
	 * @param args
	 * @returns {Promise}
	 */
	decrypt(...args)
	{
		return this.subtle.decrypt(...args);
	}
	//**********************************************************************************
	/**
	 * Wrapper for standard function "sign"
	 * @param args
	 * @returns {Promise}
	 */
	sign(...args)
	{
		return this.subtle.sign(...args);
	}
	//**********************************************************************************
	/**
	 * Wrapper for standard function "verify"
	 * @param args
	 * @returns {Promise}
	 */
	verify(...args)
	{
		return this.subtle.verify(...args);
	}
	//**********************************************************************************
	/**
	 * Wrapper for standard function "digest"
	 * @param args
	 * @returns {Promise}
	 */
	digest(...args)
	{
		return this.subtle.digest(...args);
	}
	//**********************************************************************************
	/**
	 * Wrapper for standard function "generateKey"
	 * @param args
	 * @returns {Promise}
	 */
	generateKey(...args)
	{
		return this.subtle.generateKey(...args);
	}
	//**********************************************************************************
	/**
	 * Wrapper for standard function "deriveKey"
	 * @param args
	 * @returns {Promise}
	 */
	deriveKey(...args)
	{
		return this.subtle.deriveKey(...args);
	}
	//**********************************************************************************
	/**
	 * Wrapper for standard function "deriveBits"
	 * @param args
	 * @returns {Promise}
	 */
	deriveBits(...args)
	{
		return this.subtle.deriveBits(...args);
	}
	//**********************************************************************************
	/**
	 * Wrapper for standard function "wrapKey"
	 * @param args
	 * @returns {Promise}
	 */
	wrapKey(...args)
	{
		return this.subtle.wrapKey(...args);
	}
	//**********************************************************************************
	/**
	 * Wrapper for standard function "unwrapKey"
	 * @param args
	 * @returns {Promise}
	 */
	unwrapKey(...args)
	{
		return this.subtle.unwrapKey(...args);
	}
	//**********************************************************************************
	/**
	 * Initialize input Uint8Array by random values (with help from current "crypto engine")
	 * @param {!Uint8Array} view
	 * @returns {*}
	 */
	getRandomValues(view)
	{
		if(("getRandomValues" in this.crypto) === false)
			throw new Error("No support for getRandomValues");
		
		return this.crypto.getRandomValues(view);
	}
	//**********************************************************************************
	/**
	 * Get WebCrypto algorithm by wel-known OID
	 * @param {string} oid well-known OID to search for
	 * @returns {Object}
	 */
	getAlgorithmByOID(oid)
	{
		switch(oid)
		{
			case "1.2.840.113549.1.1.1":
			case "1.2.840.113549.1.1.5":
				return {
					name: "RSASSA-PKCS1-v1_5",
					hash: {
						name: "SHA-1"
					}
				};
			case "1.2.840.113549.1.1.11":
				return {
					name: "RSASSA-PKCS1-v1_5",
					hash: {
						name: "SHA-256"
					}
				};
			case "1.2.840.113549.1.1.12":
				return {
					name: "RSASSA-PKCS1-v1_5",
					hash: {
						name: "SHA-384"
					}
				};
			case "1.2.840.113549.1.1.13":
				return {
					name: "RSASSA-PKCS1-v1_5",
					hash: {
						name: "SHA-512"
					}
				};
			case "1.2.840.113549.1.1.10":
				return {
					name: "RSA-PSS"
				};
			case "1.2.840.113549.1.1.7":
				return {
					name: "RSA-OAEP"
				};
			case "1.2.840.10045.2.1":
			case "1.2.840.10045.4.1":
				return {
					name: "ECDSA",
					hash: {
						name: "SHA-1"
					}
				};
			case "1.2.840.10045.4.3.2":
				return {
					name: "ECDSA",
					hash: {
						name: "SHA-256"
					}
				};
			case "1.2.840.10045.4.3.3":
				return {
					name: "ECDSA",
					hash: {
						name: "SHA-384"
					}
				};
			case "1.2.840.10045.4.3.4":
				return {
					name: "ECDSA",
					hash: {
						name: "SHA-512"
					}
				};
			case "1.3.133.16.840.63.0.2":
				return {
					name: "ECDH",
					kdf: "SHA-1"
				};
			case "1.3.132.1.11.1":
				return {
					name: "ECDH",
					kdf: "SHA-256"
				};
			case "1.3.132.1.11.2":
				return {
					name: "ECDH",
					kdf: "SHA-384"
				};
			case "1.3.132.1.11.3":
				return {
					name: "ECDH",
					kdf: "SHA-512"
				};
			case "2.16.840.1.101.3.4.1.2":
				return {
					name: "AES-CBC",
					length: 128
				};
			case "2.16.840.1.101.3.4.1.22":
				return {
					name: "AES-CBC",
					length: 192
				};
			case "2.16.840.1.101.3.4.1.42":
				return {
					name: "AES-CBC",
					length: 256
				};
			case "2.16.840.1.101.3.4.1.6":
				return {
					name: "AES-GCM",
					length: 128
				};
			case "2.16.840.1.101.3.4.1.26":
				return {
					name: "AES-GCM",
					length: 192
				};
			case "2.16.840.1.101.3.4.1.46":
				return {
					name: "AES-GCM",
					length: 256
				};
			case "2.16.840.1.101.3.4.1.4":
				return {
					name: "AES-CFB",
					length: 128
				};
			case "2.16.840.1.101.3.4.1.24":
				return {
					name: "AES-CFB",
					length: 192
				};
			case "2.16.840.1.101.3.4.1.44":
				return {
					name: "AES-CFB",
					length: 256
				};
			case "2.16.840.1.101.3.4.1.5":
				return {
					name: "AES-KW",
					length: 128
				};
			case "2.16.840.1.101.3.4.1.25":
				return {
					name: "AES-KW",
					length: 192
				};
			case "2.16.840.1.101.3.4.1.45":
				return {
					name: "AES-KW",
					length: 256
				};
			case "1.2.840.113549.2.7":
				return {
					name: "HMAC",
					hash: {
						name: "SHA-1"
					}
				};
			case "1.2.840.113549.2.9":
				return {
					name: "HMAC",
					hash: {
						name: "SHA-256"
					}
				};
			case "1.2.840.113549.2.10":
				return {
					name: "HMAC",
					hash: {
						name: "SHA-384"
					}
				};
			case "1.2.840.113549.2.11":
				return {
					name: "HMAC",
					hash: {
						name: "SHA-512"
					}
				};
			case "1.2.840.113549.1.9.16.3.5":
				return {
					name: "DH"
				};
			case "1.3.14.3.2.26":
				return {
					name: "SHA-1"
				};
			case "2.16.840.1.101.3.4.2.1":
				return {
					name: "SHA-256"
				};
			case "2.16.840.1.101.3.4.2.2":
				return {
					name: "SHA-384"
				};
			case "2.16.840.1.101.3.4.2.3":
				return {
					name: "SHA-512"
				};
			case "1.2.840.113549.1.5.12":
				return {
					name: "PBKDF2"
				};
			//region Special case - OIDs for ECC curves
			case "1.2.840.10045.3.1.7":
				return {
					name: "P-256"
				};
			case "1.3.132.0.34":
				return {
					name: "P-384"
				};
			case "1.3.132.0.35":
				return {
					name: "P-521"
				};
			//endregion
			default:
		}
		
		return {};
	}
	//**********************************************************************************
	/**
	 * Get OID for each specific algorithm
	 * @param {Object} algorithm
	 * @returns {string}
	 */
	getOIDByAlgorithm(algorithm)
	{
		let result = "";
		
		switch(algorithm.name.toUpperCase())
		{
			case "RSASSA-PKCS1-V1_5":
				switch(algorithm.hash.name.toUpperCase())
				{
					case "SHA-1":
						result = "1.2.840.113549.1.1.5";
						break;
					case "SHA-256":
						result = "1.2.840.113549.1.1.11";
						break;
					case "SHA-384":
						result = "1.2.840.113549.1.1.12";
						break;
					case "SHA-512":
						result = "1.2.840.113549.1.1.13";
						break;
					default:
				}
				break;
			case "RSA-PSS":
				result = "1.2.840.113549.1.1.10";
				break;
			case "RSA-OAEP":
				result = "1.2.840.113549.1.1.7";
				break;
			case "ECDSA":
				switch(algorithm.hash.name.toUpperCase())
				{
					case "SHA-1":
						result = "1.2.840.10045.4.1";
						break;
					case "SHA-256":
						result = "1.2.840.10045.4.3.2";
						break;
					case "SHA-384":
						result = "1.2.840.10045.4.3.3";
						break;
					case "SHA-512":
						result = "1.2.840.10045.4.3.4";
						break;
					default:
				}
				break;
			case "ECDH":
				switch(algorithm.kdf.toUpperCase()) // Non-standard addition - hash algorithm of KDF function
				{
					case "SHA-1":
						result = "1.3.133.16.840.63.0.2"; // dhSinglePass-stdDH-sha1kdf-scheme
						break;
					case "SHA-256":
						result = "1.3.132.1.11.1"; // dhSinglePass-stdDH-sha256kdf-scheme
						break;
					case "SHA-384":
						result = "1.3.132.1.11.2"; // dhSinglePass-stdDH-sha384kdf-scheme
						break;
					case "SHA-512":
						result = "1.3.132.1.11.3"; // dhSinglePass-stdDH-sha512kdf-scheme
						break;
					default:
				}
				break;
			case "AES-CTR":
				break;
			case "AES-CBC":
				switch(algorithm.length)
				{
					case 128:
						result = "2.16.840.1.101.3.4.1.2";
						break;
					case 192:
						result = "2.16.840.1.101.3.4.1.22";
						break;
					case 256:
						result = "2.16.840.1.101.3.4.1.42";
						break;
					default:
				}
				break;
			case "AES-CMAC":
				break;
			case "AES-GCM":
				switch(algorithm.length)
				{
					case 128:
						result = "2.16.840.1.101.3.4.1.6";
						break;
					case 192:
						result = "2.16.840.1.101.3.4.1.26";
						break;
					case 256:
						result = "2.16.840.1.101.3.4.1.46";
						break;
					default:
				}
				break;
			case "AES-CFB":
				switch(algorithm.length)
				{
					case 128:
						result = "2.16.840.1.101.3.4.1.4";
						break;
					case 192:
						result = "2.16.840.1.101.3.4.1.24";
						break;
					case 256:
						result = "2.16.840.1.101.3.4.1.44";
						break;
					default:
				}
				break;
			case "AES-KW":
				switch(algorithm.length)
				{
					case 128:
						result = "2.16.840.1.101.3.4.1.5";
						break;
					case 192:
						result = "2.16.840.1.101.3.4.1.25";
						break;
					case 256:
						result = "2.16.840.1.101.3.4.1.45";
						break;
					default:
				}
				break;
			case "HMAC":
				switch(algorithm.hash.name.toUpperCase())
				{
					case "SHA-1":
						result = "1.2.840.113549.2.7";
						break;
					case "SHA-256":
						result = "1.2.840.113549.2.9";
						break;
					case "SHA-384":
						result = "1.2.840.113549.2.10";
						break;
					case "SHA-512":
						result = "1.2.840.113549.2.11";
						break;
					default:
				}
				break;
			case "DH":
				result = "1.2.840.113549.1.9.16.3.5";
				break;
			case "SHA-1":
				result = "1.3.14.3.2.26";
				break;
			case "SHA-256":
				result = "2.16.840.1.101.3.4.2.1";
				break;
			case "SHA-384":
				result = "2.16.840.1.101.3.4.2.2";
				break;
			case "SHA-512":
				result = "2.16.840.1.101.3.4.2.3";
				break;
			case "CONCAT":
				break;
			case "HKDF":
				break;
			case "PBKDF2":
				result = "1.2.840.113549.1.5.12";
				break;
			//region Special case - OIDs for ECC curves
			case "P-256":
				result = "1.2.840.10045.3.1.7";
				break;
			case "P-384":
				result = "1.3.132.0.34";
				break;
			case "P-521":
				result = "1.3.132.0.35";
				break;
			//endregion
			default:
		}
		
		return result;
	}
	//**********************************************************************************
	/**
	 * Get default algorithm parameters for each kind of operation
	 * @param {string} algorithmName Algorithm name to get common parameters for
	 * @param {string} operation Kind of operation: "sign", "encrypt", "generatekey", "importkey", "exportkey", "verify"
	 * @returns {*}
	 */
	getAlgorithmParameters(algorithmName, operation)
	{
		let result = {
			algorithm: {},
			usages: []
		};
		
		switch(algorithmName.toUpperCase())
		{
			case "RSASSA-PKCS1-V1_5":
				switch(operation.toLowerCase())
				{
					case "generatekey":
						result = {
							algorithm: {
								name: "RSASSA-PKCS1-v1_5",
								modulusLength: 2048,
								publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
								hash: {
									name: "SHA-256"
								}
							},
							usages: ["sign", "verify"]
						};
						break;
					case "verify":
					case "sign":
					case "importkey":
						result = {
							algorithm: {
								name: "RSASSA-PKCS1-v1_5",
								hash: {
									name: "SHA-256"
								}
							},
							usages: ["verify"] // For importKey("pkcs8") usage must be "sign" only
						};
						break;
					case "exportkey":
					default:
						return {
							algorithm: {
								name: "RSASSA-PKCS1-v1_5"
							},
							usages: []
						};
				}
				break;
			case "RSA-PSS":
				switch(operation.toLowerCase())
				{
					case "sign":
					case "verify":
						result = {
							algorithm: {
								name: "RSA-PSS",
								hash: {
									name: "SHA-1"
								},
								saltLength: 20
							},
							usages: ["sign", "verify"]
						};
						break;
					case "generatekey":
						result = {
							algorithm: {
								name: "RSA-PSS",
								modulusLength: 2048,
								publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
								hash: {
									name: "SHA-1"
								}
							},
							usages: ["sign", "verify"]
						};
						break;
					case "importkey":
						result = {
							algorithm: {
								name: "RSA-PSS",
								hash: {
									name: "SHA-1"
								}
							},
							usages: ["verify"] // For importKey("pkcs8") usage must be "sign" only
						};
						break;
					case "exportkey":
					default:
						return {
							algorithm: {
								name: "RSA-PSS"
							},
							usages: []
						};
				}
				break;
			case "RSA-OAEP":
				switch(operation.toLowerCase())
				{
					case "encrypt":
					case "decrypt":
						result = {
							algorithm: {
								name: "RSA-OAEP"
							},
							usages: ["encrypt", "decrypt"]
						};
						break;
					case "generatekey":
						result = {
							algorithm: {
								name: "RSA-OAEP",
								modulusLength: 2048,
								publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
								hash: {
									name: "SHA-256"
								}
							},
							usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
						};
						break;
					case "importkey":
						result = {
							algorithm: {
								name: "RSA-OAEP",
								hash: {
									name: "SHA-256"
								}
							},
							usages: ["encrypt"] // encrypt for "spki" and decrypt for "pkcs8"
						};
						break;
					case "exportkey":
					default:
						return {
							algorithm: {
								name: "RSA-OAEP"
							},
							usages: []
						};
				}
				break;
			case "ECDSA":
				switch(operation.toLowerCase())
				{
					case "generatekey":
						result = {
							algorithm: {
								name: "ECDSA",
								namedCurve: "P-256"
							},
							usages: ["sign", "verify"]
						};
						break;
					case "importkey":
						result = {
							algorithm: {
								name: "ECDSA",
								namedCurve: "P-256"
							},
							usages: ["verify"] // "sign" for "pkcs8"
						};
						break;
					case "verify":
					case "sign":
						result = {
							algorithm: {
								name: "ECDSA",
								hash: {
									name: "SHA-256"
								}
							},
							usages: ["sign"]
						};
						break;
					default:
						return {
							algorithm: {
								name: "ECDSA"
							},
							usages: []
						};
				}
				break;
			case "ECDH":
				switch(operation.toLowerCase())
				{
					case "exportkey":
					case "importkey":
					case "generatekey":
						result = {
							algorithm: {
								name: "ECDH",
								namedCurve: "P-256"
							},
							usages: ["deriveKey", "deriveBits"]
						};
						break;
					case "derivekey":
					case "derivebits":
						result = {
							algorithm: {
								name: "ECDH",
								namedCurve: "P-256",
								public: [] // Must be a "publicKey"
							},
							usages: ["encrypt", "decrypt"]
						};
						break;
					default:
						return {
							algorithm: {
								name: "ECDH"
							},
							usages: []
						};
				}
				break;
			case "AES-CTR":
				switch(operation.toLowerCase())
				{
					case "importkey":
					case "exportkey":
					case "generatekey":
						result = {
							algorithm: {
								name: "AES-CTR",
								length: 256
							},
							usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
						};
						break;
					case "decrypt":
					case "encrypt":
						result = {
							algorithm: {
								name: "AES-CTR",
								counter: new Uint8Array(16),
								length: 10
							},
							usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
						};
						break;
					default:
						return {
							algorithm: {
								name: "AES-CTR"
							},
							usages: []
						};
				}
				break;
			case "AES-CBC":
				switch(operation.toLowerCase())
				{
					case "importkey":
					case "exportkey":
					case "generatekey":
						result = {
							algorithm: {
								name: "AES-CBC",
								length: 256
							},
							usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
						};
						break;
					case "decrypt":
					case "encrypt":
						result = {
							algorithm: {
								name: "AES-CBC",
								iv: this.getRandomValues(new Uint8Array(16)) // For "decrypt" the value should be replaced with value got on "encrypt" step
							},
							usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
						};
						break;
					default:
						return {
							algorithm: {
								name: "AES-CBC"
							},
							usages: []
						};
				}
				break;
			case "AES-GCM":
				switch(operation.toLowerCase())
				{
					case "importkey":
					case "exportkey":
					case "generatekey":
						result = {
							algorithm: {
								name: "AES-GCM",
								length: 256
							},
							usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
						};
						break;
					case "decrypt":
					case "encrypt":
						result = {
							algorithm: {
								name: "AES-GCM",
								iv: this.getRandomValues(new Uint8Array(16)) // For "decrypt" the value should be replaced with value got on "encrypt" step
							},
							usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
						};
						break;
					default:
						return {
							algorithm: {
								name: "AES-GCM"
							},
							usages: []
						};
				}
				break;
			case "AES-KW":
				switch(operation.toLowerCase())
				{
					case "importkey":
					case "exportkey":
					case "generatekey":
					case "wrapkey":
					case "unwrapkey":
						result = {
							algorithm: {
								name: "AES-KW",
								length: 256
							},
							usages: ["wrapKey", "unwrapKey"]
						};
						break;
					default:
						return {
							algorithm: {
								name: "AES-KW"
							},
							usages: []
						};
				}
				break;
			case "HMAC":
				switch(operation.toLowerCase())
				{
					case "sign":
					case "verify":
						result = {
							algorithm: {
								name: "HMAC"
							},
							usages: ["sign", "verify"]
						};
						break;
					case "importkey":
					case "exportkey":
					case "generatekey":
						result = {
							algorithm: {
								name: "HMAC",
								length: 32,
								hash: {
									name: "SHA-256"
								}
							},
							usages: ["sign", "verify"]
						};
						break;
					default:
						return {
							algorithm: {
								name: "HMAC"
							},
							usages: []
						};
				}
				break;
			case "HKDF":
				switch(operation.toLowerCase())
				{
					case "derivekey":
						result = {
							algorithm: {
								name: "HKDF",
								hash: "SHA-256",
								salt: new Uint8Array([]),
								info: new Uint8Array([])
							},
							usages: ["encrypt", "decrypt"]
						};
						break;
					default:
						return {
							algorithm: {
								name: "HKDF"
							},
							usages: []
						};
				}
				break;
			case "PBKDF2":
				switch(operation.toLowerCase())
				{
					case "derivekey":
						result = {
							algorithm: {
								name: "PBKDF2",
								hash: { name: "SHA-256" },
								salt: new Uint8Array([]),
								iterations: 10000
							},
							usages: ["encrypt", "decrypt"]
						};
						break;
					default:
						return {
							algorithm: {
								name: "PBKDF2"
							},
							usages: []
						};
				}
				break;
			default:
		}
		
		return result;
	}
	//**********************************************************************************
	/**
	 * Getting hash algorithm by signature algorithm
	 * @param {AlgorithmIdentifier} signatureAlgorithm Signature algorithm
	 * @returns {string}
	 */
	getHashAlgorithm(signatureAlgorithm)
	{
		let result = "";
		
		switch(signatureAlgorithm.algorithmId)
		{
			case "1.2.840.10045.4.1": // ecdsa-with-SHA1
			case "1.2.840.113549.1.1.5":
				result = "SHA-1";
				break;
			case "1.2.840.10045.4.3.2": // ecdsa-with-SHA256
			case "1.2.840.113549.1.1.11":
				result = "SHA-256";
				break;
			case "1.2.840.10045.4.3.3": // ecdsa-with-SHA384
			case "1.2.840.113549.1.1.12":
				result = "SHA-384";
				break;
			case "1.2.840.10045.4.3.4": // ecdsa-with-SHA512
			case "1.2.840.113549.1.1.13":
				result = "SHA-512";
				break;
			case "1.2.840.113549.1.1.10": // RSA-PSS
				{
					try
					{
						const params = new RSASSAPSSParams({ schema: signatureAlgorithm.algorithmParams });
						if("hashAlgorithm" in params)
						{
							const algorithm = this.getAlgorithmByOID(params.hashAlgorithm.algorithmId);
							if(("name" in algorithm) === false)
								return "";
							
							result = algorithm.name;
						}
						else
							result = "SHA-1";
					}
					catch(ex)
					{
					}
				}
				break;
			default:
		}
		
		return result;
	}
	//**********************************************************************************
	/**
	 * Specialized function encrypting "EncryptedContentInfo" object using parameters
	 * @param {Object} parameters
	 * @returns {Promise}
	 */
	encryptEncryptedContentInfo(parameters)
	{
		//region Check for input parameters
		if((parameters instanceof Object) === false)
			return Promise.reject("Parameters must have type \"Object\"");
		
		if(("password" in parameters) === false)
			return Promise.reject("Absent mandatory parameter \"password\"");
		
		if(("contentEncryptionAlgorithm" in parameters) === false)
			return Promise.reject("Absent mandatory parameter \"contentEncryptionAlgorithm\"");
		
		if(("hmacHashAlgorithm" in parameters) === false)
			return Promise.reject("Absent mandatory parameter \"hmacHashAlgorithm\"");
		
		if(("iterationCount" in parameters) === false)
			return Promise.reject("Absent mandatory parameter \"iterationCount\"");
		
		if(("contentToEncrypt" in parameters) === false)
			return Promise.reject("Absent mandatory parameter \"contentToEncrypt\"");
		
		if(("contentType" in parameters) === false)
			return Promise.reject("Absent mandatory parameter \"contentType\"");

		const contentEncryptionOID = this.getOIDByAlgorithm(parameters.contentEncryptionAlgorithm);
		if(contentEncryptionOID === "")
			return Promise.reject("Wrong \"contentEncryptionAlgorithm\" value");
		
		const pbkdf2OID = this.getOIDByAlgorithm({
			name: "PBKDF2"
		});
		if(pbkdf2OID === "")
			return Promise.reject("Can not find OID for PBKDF2");
		
		const hmacOID = this.getOIDByAlgorithm({
			name: "HMAC",
			hash: {
				name: parameters.hmacHashAlgorithm
			}
		});
		if(hmacOID === "")
			return Promise.reject(`Incorrect value for "hmacHashAlgorithm": ${parameters.hmacHashAlgorithm}`);
		//endregion
		
		//region Initial variables
		let sequence = Promise.resolve();
		
		const ivBuffer = new ArrayBuffer(16); // For AES we need IV 16 bytes long
		const ivView = new Uint8Array(ivBuffer);
		this.getRandomValues(ivView);
		
		const saltBuffer = new ArrayBuffer(64);
		const saltView = new Uint8Array(saltBuffer);
		this.getRandomValues(saltView);
		
		const contentView = new Uint8Array(parameters.contentToEncrypt);
		
		const pbkdf2Params = new PBKDF2Params({
			salt: new OctetString({ valueHex: saltBuffer }),
			iterationCount: parameters.iterationCount,
			prf: new AlgorithmIdentifier({
				algorithmId: hmacOID,
				algorithmParams: new Null()
			})
		});
		//endregion
		
		//region Derive PBKDF2 key from "password" buffer
		sequence = sequence.then(() =>
		{
			const passwordView = new Uint8Array(parameters.password);
			
			return this.importKey("raw",
				passwordView,
				"PBKDF2",
				false,
				["deriveKey"]);
		}, error =>
			Promise.reject(error)
		);
		//endregion
		
		//region Derive key for "contentEncryptionAlgorithm"
		sequence = sequence.then(result =>
			this.deriveKey({
				name: "PBKDF2",
				hash: {
					name: parameters.hmacHashAlgorithm
				},
				salt: saltView,
				iterations: parameters.iterationCount
			},
			result,
			parameters.contentEncryptionAlgorithm,
			false,
			["encrypt"]),
		error =>
			Promise.reject(error)
		);
		//endregion
		
		//region Encrypt content
		sequence = sequence.then(result =>
			this.encrypt({
				name: parameters.contentEncryptionAlgorithm.name,
				iv: ivView
			},
			result,
			contentView),
		error =>
			Promise.reject(error)
		);
		//endregion
		
		//region Store all parameters in EncryptedData object
		sequence = sequence.then(result =>
		{
			const pbes2Parameters = new PBES2Params({
				keyDerivationFunc: new AlgorithmIdentifier({
					algorithmId: pbkdf2OID,
					algorithmParams: pbkdf2Params.toSchema()
				}),
				encryptionScheme: new AlgorithmIdentifier({
					algorithmId: contentEncryptionOID,
					algorithmParams: new OctetString({ valueHex: ivBuffer })
				})
			});
			
			return new EncryptedContentInfo({
				contentType: parameters.contentType,
				contentEncryptionAlgorithm: new AlgorithmIdentifier({
					algorithmId: "1.2.840.113549.1.5.13", // pkcs5PBES2
					algorithmParams: pbes2Parameters.toSchema()
				}),
				encryptedContent: new OctetString({ valueHex: result })
			});
		}, error =>
			Promise.reject(error)
		);
		//endregion

		return sequence;
	}
	//**********************************************************************************
	/**
	 * Decrypt data stored in "EncryptedContentInfo" object using parameters
	 * @param parameters
	 * @return {Promise}
	 */
	decryptEncryptedContentInfo(parameters)
	{
		//region Check for input parameters
		if((parameters instanceof Object) === false)
			return Promise.reject("Parameters must have type \"Object\"");
		
		if(("password" in parameters) === false)
			return Promise.reject("Absent mandatory parameter \"password\"");
		
		if(("encryptedContentInfo" in parameters) === false)
			return Promise.reject("Absent mandatory parameter \"encryptedContentInfo\"");

		if(parameters.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId !== "1.2.840.113549.1.5.13") // pkcs5PBES2
			return Promise.reject(`Unknown "contentEncryptionAlgorithm": ${parameters.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId}`);
		//endregion
		
		//region Initial variables
		let sequence = Promise.resolve();
		
		let pbes2Parameters;
		
		try
		{
			pbes2Parameters = new PBES2Params({ schema: parameters.encryptedContentInfo.contentEncryptionAlgorithm.algorithmParams });
		}
		catch(ex)
		{
			return Promise.reject("Incorrectly encoded \"pbes2Parameters\"");
		}
		
		let pbkdf2Params;
		
		try
		{
			pbkdf2Params = new PBKDF2Params({ schema: pbes2Parameters.keyDerivationFunc.algorithmParams });
		}
		catch(ex)
		{
			return Promise.reject("Incorrectly encoded \"pbkdf2Params\"");
		}
		
		const contentEncryptionAlgorithm = this.getAlgorithmByOID(pbes2Parameters.encryptionScheme.algorithmId);
		if(("name" in contentEncryptionAlgorithm) === false)
			return Promise.reject(`Incorrect OID for "contentEncryptionAlgorithm": ${pbes2Parameters.encryptionScheme.algorithmId}`);
		
		const ivBuffer = pbes2Parameters.encryptionScheme.algorithmParams.valueBlock.valueHex;
		const ivView = new Uint8Array(ivBuffer);
		
		const saltBuffer = pbkdf2Params.salt.valueBlock.valueHex;
		const saltView = new Uint8Array(saltBuffer);
		
		const iterationCount = pbkdf2Params.iterationCount;
		
		let hmacHashAlgorithm = "SHA-1";
		
		if("prf" in pbkdf2Params)
		{
			const algorithm = this.getAlgorithmByOID(pbkdf2Params.prf.algorithmId);
			if(("name" in algorithm) === false)
				return Promise.reject("Incorrect OID for HMAC hash algorithm");
			
			hmacHashAlgorithm = algorithm.hash.name;
		}
		//endregion
		
		//region Derive PBKDF2 key from "password" buffer
		sequence = sequence.then(() =>
			this.importKey("raw",
				parameters.password,
				"PBKDF2",
				false,
				["deriveKey"]),
		error =>
			Promise.reject(error)
		);
		//endregion
		
		//region Derive key for "contentEncryptionAlgorithm"
		sequence = sequence.then(result =>
			this.deriveKey({
				name: "PBKDF2",
				hash: {
					name: hmacHashAlgorithm
				},
				salt: saltView,
				iterations: iterationCount
			},
			result,
			contentEncryptionAlgorithm,
			false,
			["decrypt"]),
		error =>
			Promise.reject(error)
		);
		//endregion
		
		//region Decrypt internal content using derived key
		sequence = sequence.then(result =>
		{
			//region Create correct data block for decryption
			let dataBuffer = new ArrayBuffer(0);
			
			if(parameters.encryptedContentInfo.encryptedContent.idBlock.isConstructed === false)
				dataBuffer = parameters.encryptedContentInfo.encryptedContent.valueBlock.valueHex;
			else
			{
				for(const content of parameters.encryptedContentInfo.encryptedContent.valueBlock.value)
					dataBuffer = utilConcatBuf(dataBuffer, content.valueBlock.valueHex);
			}
			//endregion
			
			return this.decrypt({
				name: contentEncryptionAlgorithm.name,
				iv: ivView
			},
			result,
			dataBuffer);
		}, error =>
			Promise.reject(error)
		);
		//endregion
		
		return sequence;
	}
	//**********************************************************************************
	/**
	 * Stamping (signing) data using algorithm simular to HMAC
	 * @param {Object} parameters
	 * @return {Promise.<T>|Promise}
	 */
	stampDataWithPassword(parameters)
	{
		//region Check for input parameters
		if((parameters instanceof Object) === false)
			return Promise.reject("Parameters must have type \"Object\"");
		
		if(("password" in parameters) === false)
			return Promise.reject("Absent mandatory parameter \"password\"");
		
		if(("hashAlgorithm" in parameters) === false)
			return Promise.reject("Absent mandatory parameter \"hashAlgorithm\"");
		
		if(("salt" in parameters) === false)
			return Promise.reject("Absent mandatory parameter \"iterationCount\"");
		
		if(("iterationCount" in parameters) === false)
			return Promise.reject("Absent mandatory parameter \"salt\"");
		
		if(("contentToStamp" in parameters) === false)
			return Promise.reject("Absent mandatory parameter \"contentToStamp\"");
		//endregion
		
		//region Choose correct length for HMAC key
		let length;
		
		switch(parameters.hashAlgorithm.toLowerCase())
		{
			case "sha-1":
				length = 160;
				break;
			case "sha-256":
				length = 256;
				break;
			case "sha-384":
				length = 384;
				break;
			case "sha-512":
				length = 512;
				break;
			default:
				return Promise.reject(`Incorrect "parameters.hashAlgorithm" parameter: ${parameters.hashAlgorithm}`);
		}
		//endregion
		
		//region Initial variables
		let sequence = Promise.resolve();
		
		const hmacAlgorithm = {
			name: "HMAC",
			length,
			hash: {
				name: parameters.hashAlgorithm
			}
		};
		//endregion

		//region Create PKCS#12 key for integrity checking
		sequence = sequence.then(() => makePKCS12B2Key(this, parameters.hashAlgorithm, length, parameters.password, parameters.salt, parameters.iterationCount));
		//endregion
		
		//region Import HMAC key
		// noinspection JSCheckFunctionSignatures
		sequence = sequence.then(
			result =>
				this.importKey("raw",
					new Uint8Array(result),
					hmacAlgorithm,
					false,
					["sign"])
		);
		//endregion
		
		//region Make signed HMAC value
		sequence = sequence.then(
			result =>
				this.sign(hmacAlgorithm, result, new Uint8Array(parameters.contentToStamp)),
			error => Promise.reject(error)
		);
		//endregion

		return sequence;
	}
	//**********************************************************************************
	verifyDataStampedWithPassword(parameters)
	{
		//region Check for input parameters
		if((parameters instanceof Object) === false)
			return Promise.reject("Parameters must have type \"Object\"");
		
		if(("password" in parameters) === false)
			return Promise.reject("Absent mandatory parameter \"password\"");
		
		if(("hashAlgorithm" in parameters) === false)
			return Promise.reject("Absent mandatory parameter \"hashAlgorithm\"");
		
		if(("salt" in parameters) === false)
			return Promise.reject("Absent mandatory parameter \"iterationCount\"");
		
		if(("iterationCount" in parameters) === false)
			return Promise.reject("Absent mandatory parameter \"salt\"");
		
		if(("contentToVerify" in parameters) === false)
			return Promise.reject("Absent mandatory parameter \"contentToVerify\"");
		
		if(("signatureToVerify" in parameters) === false)
			return Promise.reject("Absent mandatory parameter \"signatureToVerify\"");
		//endregion
		
		//region Choose correct length for HMAC key
		let length;
		
		switch(parameters.hashAlgorithm.toLowerCase())
		{
			case "sha-1":
				length = 160;
				break;
			case "sha-256":
				length = 256;
				break;
			case "sha-384":
				length = 384;
				break;
			case "sha-512":
				length = 512;
				break;
			default:
				return Promise.reject(`Incorrect "parameters.hashAlgorithm" parameter: ${parameters.hashAlgorithm}`);
		}
		//endregion
		
		//region Initial variables
		let sequence = Promise.resolve();
		
		const hmacAlgorithm = {
			name: "HMAC",
			length,
			hash: {
				name: parameters.hashAlgorithm
			}
		};
		//endregion
		
		//region Create PKCS#12 key for integrity checking
		sequence = sequence.then(() => makePKCS12B2Key(this, parameters.hashAlgorithm, length, parameters.password, parameters.salt, parameters.iterationCount));
		//endregion
		
		//region Import HMAC key
		// noinspection JSCheckFunctionSignatures
		sequence = sequence.then(result =>
			this.importKey("raw",
				new Uint8Array(result),
				hmacAlgorithm,
				false,
				["verify"])
		);
		//endregion
		
		//region Make signed HMAC value
		sequence = sequence.then(
			result =>
				this.verify(hmacAlgorithm, result, new Uint8Array(parameters.signatureToVerify), new Uint8Array(parameters.contentToVerify)),
			error => Promise.reject(error)
		);
		//endregion
		
		return sequence;
	}
	//**********************************************************************************
	/**
	 * Get signature parameters by analyzing private key algorithm
	 * @param {Object} privateKey The private key user would like to use
	 * @param {string} [hashAlgorithm="SHA-1"] Hash algorithm user would like to use
	 * @return {Promise.<T>|Promise}
	 */
	getSignatureParameters(privateKey, hashAlgorithm = "SHA-1")
	{
		//region Check hashing algorithm
		const oid = this.getOIDByAlgorithm({ name: hashAlgorithm });
		if(oid === "")
			return Promise.reject(`Unsupported hash algorithm: ${hashAlgorithm}`);
		//endregion
		
		//region Initial variables
		const signatureAlgorithm = new AlgorithmIdentifier();
		//endregion
		
		//region Get a "default parameters" for current algorithm
		const parameters = this.getAlgorithmParameters(privateKey.algorithm.name, "sign");
		parameters.algorithm.hash.name = hashAlgorithm;
		//endregion
		
		//region Fill internal structures base on "privateKey" and "hashAlgorithm"
		switch(privateKey.algorithm.name.toUpperCase())
		{
			case "RSASSA-PKCS1-V1_5":
			case "ECDSA":
				signatureAlgorithm.algorithmId = this.getOIDByAlgorithm(parameters.algorithm);
				break;
			case "RSA-PSS":
				{
					//region Set "saltLength" as a length (in octets) of hash function result
					switch(hashAlgorithm.toUpperCase())
					{
						case "SHA-256":
							parameters.algorithm.saltLength = 32;
							break;
						case "SHA-384":
							parameters.algorithm.saltLength = 48;
							break;
						case "SHA-512":
							parameters.algorithm.saltLength = 64;
							break;
						default:
					}
					//endregion
					
					//region Fill "RSASSA_PSS_params" object
					const paramsObject = {};
					
					if(hashAlgorithm.toUpperCase() !== "SHA-1")
					{
						const hashAlgorithmOID = this.getOIDByAlgorithm({ name: hashAlgorithm });
						if(hashAlgorithmOID === "")
							return Promise.reject(`Unsupported hash algorithm: ${hashAlgorithm}`);
						
						paramsObject.hashAlgorithm = new AlgorithmIdentifier({
							algorithmId: hashAlgorithmOID,
							algorithmParams: new Null()
						});
						
						paramsObject.maskGenAlgorithm = new AlgorithmIdentifier({
							algorithmId: "1.2.840.113549.1.1.8", // MGF1
							algorithmParams: paramsObject.hashAlgorithm.toSchema()
						});
					}
					
					if(parameters.algorithm.saltLength !== 20)
						paramsObject.saltLength = parameters.algorithm.saltLength;
					
					const pssParameters = new RSASSAPSSParams(paramsObject);
					//endregion
					
					//region Automatically set signature algorithm
					signatureAlgorithm.algorithmId = "1.2.840.113549.1.1.10";
					signatureAlgorithm.algorithmParams = pssParameters.toSchema();
					//endregion
				}
				break;
			default:
				return Promise.reject(`Unsupported signature algorithm: ${privateKey.algorithm.name}`);
		}
		//endregion

		return Promise.resolve().then(() => ({
			signatureAlgorithm,
			parameters
		}));
	}
	//**********************************************************************************
	/**
	 * Sign data with pre-defined private key
	 * @param {ArrayBuffer} data Data to be signed
	 * @param {Object} privateKey Private key to use
	 * @param {Object} parameters Parameters for used algorithm
	 * @return {Promise.<T>|Promise}
	 */
	signWithPrivateKey(data, privateKey, parameters)
	{
		return this.sign(parameters.algorithm,
			privateKey,
			new Uint8Array(data))
			.then(result =>
			{
				//region Special case for ECDSA algorithm
				if(parameters.algorithm.name === "ECDSA")
					result = createCMSECDSASignature(result);
				//endregion
				
				return result;
			}, error =>
				Promise.reject(`Signing error: ${error}`)
			);
	}
	//**********************************************************************************
	fillPublicKeyParameters(publicKeyInfo, signatureAlgorithm)
	{
		const parameters = {};
		
		//region Find signer's hashing algorithm
		const shaAlgorithm = this.getHashAlgorithm(signatureAlgorithm);
		if(shaAlgorithm === "")
			return Promise.reject(`Unsupported signature algorithm: ${signatureAlgorithm.algorithmId}`);
		//endregion
		
		//region Get information about public key algorithm and default parameters for import
		let algorithmId;
		if(signatureAlgorithm.algorithmId === "1.2.840.113549.1.1.10")
			algorithmId = signatureAlgorithm.algorithmId;
		else
			algorithmId = publicKeyInfo.algorithm.algorithmId;
		
		const algorithmObject = this.getAlgorithmByOID(algorithmId);
		if(("name" in algorithmObject) === "")
			return Promise.reject(`Unsupported public key algorithm: ${signatureAlgorithm.algorithmId}`);
		
		parameters.algorithm = this.getAlgorithmParameters(algorithmObject.name, "importkey");
		if("hash" in parameters.algorithm.algorithm)
			parameters.algorithm.algorithm.hash.name = shaAlgorithm;
		
		//region Special case for ECDSA
		if(algorithmObject.name === "ECDSA")
		{
			//region Get information about named curve
			let algorithmParamsChecked = false;
			
			if(("algorithmParams" in publicKeyInfo.algorithm) === true)
			{
				if("idBlock" in publicKeyInfo.algorithm.algorithmParams)
				{
					if((publicKeyInfo.algorithm.algorithmParams.idBlock.tagClass === 1) && (publicKeyInfo.algorithm.algorithmParams.idBlock.tagNumber === 6))
						algorithmParamsChecked = true;
				}
			}
			
			if(algorithmParamsChecked === false)
				return Promise.reject("Incorrect type for ECDSA public key parameters");
			
			const curveObject = this.getAlgorithmByOID(publicKeyInfo.algorithm.algorithmParams.valueBlock.toString());
			if(("name" in curveObject) === false)
				return Promise.reject(`Unsupported named curve algorithm: ${publicKeyInfo.algorithm.algorithmParams.valueBlock.toString()}`);
			//endregion
			
			parameters.algorithm.algorithm.namedCurve = curveObject.name;
		}
		//endregion
		//endregion
		
		return parameters;
	}
	//**********************************************************************************
	getPublicKey(publicKeyInfo, signatureAlgorithm, parameters = null)
	{
		if(parameters === null)
			parameters = this.fillPublicKeyParameters(publicKeyInfo, signatureAlgorithm);
		
		const publicKeyInfoSchema = publicKeyInfo.toSchema();
		const publicKeyInfoBuffer = publicKeyInfoSchema.toBER(false);
		const publicKeyInfoView = new Uint8Array(publicKeyInfoBuffer);
		
		return this.importKey("spki",
			publicKeyInfoView,
			parameters.algorithm.algorithm,
			true,
			parameters.algorithm.usages
		);
	}
	//**********************************************************************************
	verifyWithPublicKey(data, signature, publicKeyInfo, signatureAlgorithm, shaAlgorithm = null)
	{
		//region Initial variables
		let sequence = Promise.resolve();
		//endregion
		
		//region Find signer's hashing algorithm
		if(shaAlgorithm === null)
		{
			shaAlgorithm = this.getHashAlgorithm(signatureAlgorithm);
			if(shaAlgorithm === "")
				return Promise.reject(`Unsupported signature algorithm: ${signatureAlgorithm.algorithmId}`);
			
			//region Import public key
			sequence = sequence.then(() =>
				this.getPublicKey(publicKeyInfo, signatureAlgorithm));
			//endregion
		}
		else
		{
			const parameters = {};
			
			//region Get information about public key algorithm and default parameters for import
			let algorithmId;
			if(signatureAlgorithm.algorithmId === "1.2.840.113549.1.1.10")
				algorithmId = signatureAlgorithm.algorithmId;
			else
				algorithmId = publicKeyInfo.algorithm.algorithmId;
			
			const algorithmObject = this.getAlgorithmByOID(algorithmId);
			if(("name" in algorithmObject) === "")
				return Promise.reject(`Unsupported public key algorithm: ${signatureAlgorithm.algorithmId}`);
			
			parameters.algorithm = this.getAlgorithmParameters(algorithmObject.name, "importkey");
			if("hash" in parameters.algorithm.algorithm)
				parameters.algorithm.algorithm.hash.name = shaAlgorithm;
			
			//region Special case for ECDSA
			if(algorithmObject.name === "ECDSA")
			{
				//region Get information about named curve
				let algorithmParamsChecked = false;
				
				if(("algorithmParams" in publicKeyInfo.algorithm) === true)
				{
					if("idBlock" in publicKeyInfo.algorithm.algorithmParams)
					{
						if((publicKeyInfo.algorithm.algorithmParams.idBlock.tagClass === 1) && (publicKeyInfo.algorithm.algorithmParams.idBlock.tagNumber === 6))
							algorithmParamsChecked = true;
					}
				}
				
				if(algorithmParamsChecked === false)
					return Promise.reject("Incorrect type for ECDSA public key parameters");
				
				const curveObject = this.getAlgorithmByOID(publicKeyInfo.algorithm.algorithmParams.valueBlock.toString());
				if(("name" in curveObject) === false)
					return Promise.reject(`Unsupported named curve algorithm: ${publicKeyInfo.algorithm.algorithmParams.valueBlock.toString()}`);
				//endregion
				
				parameters.algorithm.algorithm.namedCurve = curveObject.name;
			}
			//endregion
			//endregion

			//region Import public key
			sequence = sequence.then(() =>
				this.getPublicKey(publicKeyInfo, null, parameters));
			//endregion
		}
		//endregion
		
		//region Verify signature
		sequence = sequence.then(publicKey =>
		{
			//region Get default algorithm parameters for verification
			const algorithm = this.getAlgorithmParameters(publicKey.algorithm.name, "verify");
			if("hash" in algorithm.algorithm)
				algorithm.algorithm.hash.name = shaAlgorithm;
			//endregion
			
			//region Special case for ECDSA signatures
			let signatureValue = signature.valueBlock.valueHex;
			
			if(publicKey.algorithm.name === "ECDSA")
			{
				const asn1 = fromBER(signatureValue);
				signatureValue = createECDSASignatureFromCMS(asn1.result);
			}
			//endregion
			
			//region Special case for RSA-PSS
			if(publicKey.algorithm.name === "RSA-PSS")
			{
				let pssParameters;
				
				try
				{
					pssParameters = new RSASSAPSSParams({ schema: signatureAlgorithm.algorithmParams });
				}
				catch(ex)
				{
					return Promise.reject(ex);
				}
				
				if("saltLength" in pssParameters)
					algorithm.algorithm.saltLength = pssParameters.saltLength;
				else
					algorithm.algorithm.saltLength = 20;
				
				let hashAlgo = "SHA-1";
				
				if("hashAlgorithm" in pssParameters)
				{
					const hashAlgorithm = this.getAlgorithmByOID(pssParameters.hashAlgorithm.algorithmId);
					if(("name" in hashAlgorithm) === false)
						return Promise.reject(`Unrecognized hash algorithm: ${pssParameters.hashAlgorithm.algorithmId}`);
					
					hashAlgo = hashAlgorithm.name;
				}
				
				algorithm.algorithm.hash.name = hashAlgo;
			}
			//endregion
			
			return this.verify(algorithm.algorithm,
				publicKey,
				new Uint8Array(signatureValue),
				new Uint8Array(data)
			);
		});
		//endregion
		
		return sequence;
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
//region Crypto engine related function
//**************************************************************************************
let engine = {
	name: "none",
	crypto: null,
	subtle: null
};
//**************************************************************************************

//**************************************************************************************
function getEngine()
{
	return engine;
}
//**************************************************************************************
(function initCryptoEngine()
{
	if(typeof self !== "undefined")
	{
		if("crypto" in self)
		{
			let engineName = "webcrypto";
				
			/**
			 * Standard crypto object
			 * @type {Object}
			 * @property {Object} [webkitSubtle] Subtle object from Apple
			 */
			const cryptoObject = self.crypto;
			let subtleObject = null;
				
			// Apple Safari support
			if("webkitSubtle" in self.crypto)
			{
				try
				{
					subtleObject = self.crypto.webkitSubtle;
				}
				catch(ex)
				{
					subtleObject = self.crypto.subtle;
				}
				
				engineName = "safari";
			}
				
			if("subtle" in self.crypto)
				subtleObject = self.crypto.subtle;
				
			engine = {
				name: engineName,
				crypto: cryptoObject,
				subtle: new CryptoEngine({ name: engineName, crypto: self.crypto, subtle: subtleObject })
			};
		}
	}
})();
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of common functions
//**************************************************************************************
/**
 * Get crypto subtle from current "crypto engine" or "undefined"
 * @returns {({decrypt, deriveKey, digest, encrypt, exportKey, generateKey, importKey, sign, unwrapKey, verify, wrapKey}|null)}
 */
function getCrypto()
{
	if(engine.subtle !== null)
		return engine.subtle;
	
	return undefined;
}
//**************************************************************************************
/**
 * Initialize input Uint8Array by random values (with help from current "crypto engine")
 * @param {!Uint8Array} view
 * @returns {*}
 */

//**************************************************************************************
/**
 * Get OID for each specific algorithm
 * @param {Object} algorithm
 * @returns {string}
 */

//**************************************************************************************
/**
 * Get default algorithm parameters for each kind of operation
 * @param {string} algorithmName Algorithm name to get common parameters for
 * @param {string} operation Kind of operation: "sign", "encrypt", "generatekey", "importkey", "exportkey", "verify"
 * @returns {*}
 */

//**************************************************************************************
/**
 * Create CMS ECDSA signature from WebCrypto ECDSA signature
 * @param {ArrayBuffer} signatureBuffer WebCrypto result of "sign" function
 * @returns {ArrayBuffer}
 */
function createCMSECDSASignature(signatureBuffer)
{
	//region Initial check for correct length
	if((signatureBuffer.byteLength % 2) !== 0)
		return new ArrayBuffer(0);
	//endregion
	
	//region Initial variables
	const length = signatureBuffer.byteLength / 2; // There are two equal parts inside incoming ArrayBuffer
	
	const rBuffer = new ArrayBuffer(length);
	const rView = new Uint8Array(rBuffer);
	rView.set(new Uint8Array(signatureBuffer, 0, length));
	
	const rInteger = new Integer({ valueHex: rBuffer });
	
	const sBuffer = new ArrayBuffer(length);
	const sView = new Uint8Array(sBuffer);
	sView.set(new Uint8Array(signatureBuffer, length, length));
	
	const sInteger = new Integer({ valueHex: sBuffer });
	//endregion
	
	return (new Sequence({
		value: [
			rInteger.convertToDER(),
			sInteger.convertToDER()
		]
	})).toBER(false);
}
//**************************************************************************************
/**
 * String preparation function. In a future here will be realization of algorithm from RFC4518
 * @param {string} inputString JavaScript string. As soon as for each ASN.1 string type we have a specific transformation function here we will work with pure JavaScript string
 * @returns {string} Formated string
 */
function stringPrep(inputString)
{
	//region Initial variables
	let isSpace = false;
	let cuttedResult = "";
	//endregion
	
	const result = inputString.trim(); // Trim input string
	
	//region Change all sequence of SPACE down to SPACE char
	for(let i = 0; i < result.length; i++)
	{
		if(result.charCodeAt(i) === 32)
		{
			if(isSpace === false)
				isSpace = true;
		}
		else
		{
			if(isSpace)
			{
				cuttedResult += " ";
				isSpace = false;
			}
			
			cuttedResult += result[i];
		}
	}
	//endregion
	
	return cuttedResult.toLowerCase();
}
//**************************************************************************************
/**
 * Create a single ArrayBuffer from CMS ECDSA signature
 * @param {Sequence} cmsSignature ASN.1 SEQUENCE contains CMS ECDSA signature
 * @returns {ArrayBuffer}
 */
function createECDSASignatureFromCMS(cmsSignature)
{
	//region Check input variables
	if((cmsSignature instanceof Sequence) === false)
		return new ArrayBuffer(0);
	
	if(cmsSignature.valueBlock.value.length !== 2)
		return new ArrayBuffer(0);
	
	if((cmsSignature.valueBlock.value[0] instanceof Integer) === false)
		return new ArrayBuffer(0);
	
	if((cmsSignature.valueBlock.value[1] instanceof Integer) === false)
		return new ArrayBuffer(0);
	//endregion 
	
	const rValue = cmsSignature.valueBlock.value[0].convertFromDER();
	const sValue = cmsSignature.valueBlock.value[1].convertFromDER();
	
	//region Check the lengths of two parts are equal
	switch(true)
	{
		case (rValue.valueBlock.valueHex.byteLength < sValue.valueBlock.valueHex.byteLength):
			{
				if((sValue.valueBlock.valueHex.byteLength - rValue.valueBlock.valueHex.byteLength) !== 1)
					throw new Error("Incorrect DER integer decoding");
				
				const correctedLength = sValue.valueBlock.valueHex.byteLength;
				
				const rValueView = new Uint8Array(rValue.valueBlock.valueHex);
				
				const rValueBufferCorrected = new ArrayBuffer(correctedLength);
				const rValueViewCorrected = new Uint8Array(rValueBufferCorrected);
				
				rValueViewCorrected.set(rValueView, 1);
				rValueViewCorrected[0] = 0x00; // In order to be sure we do not have any garbage here
				
				return utilConcatBuf(rValueBufferCorrected, sValue.valueBlock.valueHex);
			}
		case (rValue.valueBlock.valueHex.byteLength > sValue.valueBlock.valueHex.byteLength):
			{
				if((rValue.valueBlock.valueHex.byteLength - sValue.valueBlock.valueHex.byteLength) !== 1)
					throw new Error("Incorrect DER integer decoding");
				
				const correctedLength = rValue.valueBlock.valueHex.byteLength;
				
				const sValueView = new Uint8Array(sValue.valueBlock.valueHex);
				
				const sValueBufferCorrected = new ArrayBuffer(correctedLength);
				const sValueViewCorrected = new Uint8Array(sValueBufferCorrected);
				
				sValueViewCorrected.set(sValueView, 1);
				sValueViewCorrected[0] = 0x00; // In order to be sure we do not have any garbage here
				
				return utilConcatBuf(rValue.valueBlock.valueHex, sValueBufferCorrected);
			}
		default:
			{
				//region In case we have equal length and the length is not even with 2
				if(rValue.valueBlock.valueHex.byteLength % 2)
				{
					const correctedLength = (rValue.valueBlock.valueHex.byteLength + 1);
					
					const rValueView = new Uint8Array(rValue.valueBlock.valueHex);
					
					const rValueBufferCorrected = new ArrayBuffer(correctedLength);
					const rValueViewCorrected = new Uint8Array(rValueBufferCorrected);
					
					rValueViewCorrected.set(rValueView, 1);
					rValueViewCorrected[0] = 0x00; // In order to be sure we do not have any garbage here
					
					const sValueView = new Uint8Array(sValue.valueBlock.valueHex);
					
					const sValueBufferCorrected = new ArrayBuffer(correctedLength);
					const sValueViewCorrected = new Uint8Array(sValueBufferCorrected);
					
					sValueViewCorrected.set(sValueView, 1);
					sValueViewCorrected[0] = 0x00; // In order to be sure we do not have any garbage here
					
					return utilConcatBuf(rValueBufferCorrected, sValueBufferCorrected);
				}
				//endregion
			}
	}
	//endregion
	
	return utilConcatBuf(rValue.valueBlock.valueHex, sValue.valueBlock.valueHex);
}
//**************************************************************************************
/**
 * Get WebCrypto algorithm by wel-known OID
 * @param {string} oid well-known OID to search for
 * @returns {Object}
 */

//**************************************************************************************
/**
 * Getting hash algorithm by signature algorithm
 * @param {AlgorithmIdentifier} signatureAlgorithm Signature algorithm
 * @returns {string}
 */

//**************************************************************************************
/**
 * ANS X9.63 Key Derivation Function having a "Counter" as a parameter
 * @param {string} hashFunction Used hash function
 * @param {ArrayBuffer} Zbuffer ArrayBuffer containing ECDH shared secret to derive from
 * @param {number} Counter
 * @param {ArrayBuffer} SharedInfo Usually DER encoded "ECC_CMS_SharedInfo" structure
 */

//**************************************************************************************
/**
 * ANS X9.63 Key Derivation Function
 * @param {string} hashFunction Used hash function
 * @param {ArrayBuffer} Zbuffer ArrayBuffer containing ECDH shared secret to derive from
 * @param {number} keydatalen Length (!!! in BITS !!!) of used kew derivation function
 * @param {ArrayBuffer} SharedInfo Usually DER encoded "ECC_CMS_SharedInfo" structure
 */

//**************************************************************************************
//endregion
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class AttributeTypeAndValue
{
	//**********************************************************************************
	/**
	 * Constructor for AttributeTypeAndValue class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {string}
		 * @description type
		 */
		this.type = getParametersValue(parameters, "type", AttributeTypeAndValue.defaultValues("type"));
		/**
		 * @type {Object}
		 * @description Value of the AttributeTypeAndValue class
		 */
		this.value = getParametersValue(parameters, "value", AttributeTypeAndValue.defaultValues("value"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "type":
				return "";
			case "value":
				return {};
			default:
				throw new Error(`Invalid member name for AttributeTypeAndValue class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//AttributeTypeAndValue ::= Sequence {
		//    type     AttributeType,
		//    value    AttributeValue }
		//
		//AttributeType ::= OBJECT IDENTIFIER
		//
		//AttributeValue ::= ANY -- DEFINED BY AttributeType

		/**
		 * @type {Object}
		 * @property {string} [blockName] Name for entire block
		 * @property {string} [type] Name for "type" element
		 * @property {string} [value] Name for "value" element
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new ObjectIdentifier({ name: (names.type || "") }),
				new Any({ name: (names.value || "") })
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		/**
		 * @type {{verified: boolean}|{verified: boolean, result: {type: Object, typeValue: Object}}}
		 */
		const asn1 = compareSchema(schema,
			schema,
			AttributeTypeAndValue.schema({
				names: {
					type: "type",
					value: "typeValue"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for ATTR_TYPE_AND_VALUE");
		//endregion

		//region Get internal properties from parsed schema
		this.type = asn1.result.type.valueBlock.toString();
		this.value = asn1.result.typeValue;
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: [
				new ObjectIdentifier({ value: this.type }),
				this.value
			]
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		const _object = {
			type: this.type
		};

		if(Object.keys(this.value).length !== 0)
			_object.value = this.value.toJSON();
		else
			_object.value = this.value;

		return _object;
	}
	//**********************************************************************************
	/**
	 * Compare two AttributeTypeAndValue values, or AttributeTypeAndValue with ArrayBuffer value
	 * @param {(AttributeTypeAndValue|ArrayBuffer)} compareTo The value compare to current
	 * @returns {boolean}
	 */
	isEqual(compareTo)
	{
		if(compareTo instanceof AttributeTypeAndValue)
		{
			if(this.type !== compareTo.type)
				return false;
			
			// noinspection OverlyComplexBooleanExpressionJS
			if(((this.value instanceof Utf8String) && (compareTo.value instanceof Utf8String)) ||
				((this.value instanceof BmpString) && (compareTo.value instanceof BmpString)) ||
				((this.value instanceof UniversalString) && (compareTo.value instanceof UniversalString)) ||
				((this.value instanceof NumericString) && (compareTo.value instanceof NumericString)) ||
				((this.value instanceof PrintableString) && (compareTo.value instanceof PrintableString)) ||
				((this.value instanceof TeletexString) && (compareTo.value instanceof TeletexString)) ||
				((this.value instanceof VideotexString) && (compareTo.value instanceof VideotexString)) ||
				((this.value instanceof IA5String) && (compareTo.value instanceof IA5String)) ||
				((this.value instanceof GraphicString) && (compareTo.value instanceof GraphicString)) ||
				((this.value instanceof VisibleString) && (compareTo.value instanceof VisibleString)) ||
				((this.value instanceof GeneralString) && (compareTo.value instanceof GeneralString)) ||
				((this.value instanceof CharacterString) && (compareTo.value instanceof CharacterString)))
			{
				const value1 = stringPrep(this.value.valueBlock.value);
				const value2 = stringPrep(compareTo.value.valueBlock.value);
				
				if(value1.localeCompare(value2) !== 0)
					return false;
			}
			else // Comparing as two ArrayBuffers
			{
				if(isEqualBuffer(this.value.valueBeforeDecode, compareTo.value.valueBeforeDecode) === false)
					return false;
			}
			
			return true;
		}
		
		if(compareTo instanceof ArrayBuffer)
			return isEqualBuffer(this.value.valueBeforeDecode, compareTo);

		return false;
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class RelativeDistinguishedNames
{
	//**********************************************************************************
	/**
	 * Constructor for RelativeDistinguishedNames class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 * @property {Array.<AttributeTypeAndValue>} [typesAndValues] Array of "type and value" objects
	 * @property {ArrayBuffer} [valueBeforeDecode] Value of the RDN before decoding from schema
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Array.<AttributeTypeAndValue>}
		 * @description Array of "type and value" objects
		 */
		this.typesAndValues = getParametersValue(parameters, "typesAndValues", RelativeDistinguishedNames.defaultValues("typesAndValues"));
		/**
		 * @type {ArrayBuffer}
		 * @description Value of the RDN before decoding from schema
		 */
		this.valueBeforeDecode = getParametersValue(parameters, "valueBeforeDecode", RelativeDistinguishedNames.defaultValues("valueBeforeDecode"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "typesAndValues":
				return [];
			case "valueBeforeDecode":
				return new ArrayBuffer(0);
			default:
				throw new Error(`Invalid member name for RelativeDistinguishedNames class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Compare values with default values for all class members
	 * @param {string} memberName String name for a class member
	 * @param {*} memberValue Value to compare with default value
	 */
	static compareWithDefault(memberName, memberValue)
	{
		switch(memberName)
		{
			case "typesAndValues":
				return (memberValue.length === 0);
			case "valueBeforeDecode":
				return (memberValue.byteLength === 0);
			default:
				throw new Error(`Invalid member name for RelativeDistinguishedNames class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//RDNSequence ::= Sequence OF RelativeDistinguishedName
		//
		//RelativeDistinguishedName ::=
		//SET SIZE (1..MAX) OF AttributeTypeAndValue

		/**
		 * @type {Object}
		 * @property {string} [blockName] Name for entire block
		 * @property {string} [repeatedSequence] Name for "repeatedSequence" block
		 * @property {string} [repeatedSet] Name for "repeatedSet" block
		 * @property {string} [typeAndValue] Name for "typeAndValue" block
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Repeated({
					name: (names.repeatedSequence || ""),
					value: new Set({
						value: [
							new Repeated({
								name: (names.repeatedSet || ""),
								value: AttributeTypeAndValue.schema(names.typeAndValue || {})
							})
						]
					})
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		/**
		 * @type {{verified: boolean}|{verified: boolean, result: {RDN: Object, typesAndValues: Array.<Object>}}}
		 */
		const asn1 = compareSchema(schema,
			schema,
			RelativeDistinguishedNames.schema({
				names: {
					blockName: "RDN",
					repeatedSet: "typesAndValues"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for RDN");
		//endregion

		//region Get internal properties from parsed schema
		if("typesAndValues" in asn1.result) // Could be a case when there is no "types and values"
			this.typesAndValues = Array.from(asn1.result.typesAndValues, element => new AttributeTypeAndValue({ schema: element }));

		this.valueBeforeDecode = asn1.result.RDN.valueBeforeDecode;
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Decode stored TBS value
		if(this.valueBeforeDecode.byteLength === 0) // No stored encoded array, create "from scratch"
		{
			return (new Sequence({
				value: [new Set({
					value: Array.from(this.typesAndValues, element => element.toSchema())
				})]
			}));
		}

		const asn1 = fromBER(this.valueBeforeDecode);
		//endregion

		//region Construct and return new ASN.1 schema for this object
		return asn1.result;
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		return {
			typesAndValues: Array.from(this.typesAndValues, element => element.toJSON())
		};
	}
	//**********************************************************************************
	/**
	 * Compare two RDN values, or RDN with ArrayBuffer value
	 * @param {(RelativeDistinguishedNames|ArrayBuffer)} compareTo The value compare to current
	 * @returns {boolean}
	 */
	isEqual(compareTo)
	{
		if(compareTo instanceof RelativeDistinguishedNames)
		{
			if(this.typesAndValues.length !== compareTo.typesAndValues.length)
				return false;

			for(const [index, typeAndValue] of this.typesAndValues.entries())
			{
				if(typeAndValue.isEqual(compareTo.typesAndValues[index]) === false)
					return false;
			}

			return true;
		}

		if(compareTo instanceof ArrayBuffer)
			return isEqualBuffer(this.valueBeforeDecode, compareTo);

		return false;
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
//region Additional asn1js schema elements existing inside GENERAL_NAME schema
//**************************************************************************************
/**
 * Schema for "builtInStandardAttributes" of "ORAddress"
 * @param {Object} parameters
 * @property {Object} [names]
 * @param {boolean} optional
 * @returns {Sequence}
 */
function builtInStandardAttributes(parameters = {}, optional = false)
{
	//builtInStandardAttributes ::= Sequence {
	//    country-name                  CountryName OPTIONAL,
	//    administration-domain-name    AdministrationDomainName OPTIONAL,
	//    network-address           [0] IMPLICIT NetworkAddress OPTIONAL,
	//    terminal-identifier       [1] IMPLICIT TerminalIdentifier OPTIONAL,
	//    private-domain-name       [2] PrivateDomainName OPTIONAL,
	//    organization-name         [3] IMPLICIT OrganizationName OPTIONAL,
	//    numeric-user-identifier   [4] IMPLICIT NumericUserIdentifier OPTIONAL,
	//    personal-name             [5] IMPLICIT PersonalName OPTIONAL,
	//    organizational-unit-names [6] IMPLICIT OrganizationalUnitNames OPTIONAL }

	/**
	 * @type {Object}
	 * @property {string} [country_name]
	 * @property {string} [administration_domain_name]
	 * @property {string} [network_address]
	 * @property {string} [terminal_identifier]
	 * @property {string} [private_domain_name]
	 * @property {string} [organization_name]
	 * @property {string} [numeric_user_identifier]
	 * @property {string} [personal_name]
	 * @property {string} [organizational_unit_names]
	 */
	const names = getParametersValue(parameters, "names", {});

	return (new Sequence({
		optional,
		value: [
			new Constructed({
				optional: true,
				idBlock: {
					tagClass: 2, // APPLICATION-SPECIFIC
					tagNumber: 1 // [1]
				},
				name: (names.country_name || ""),
				value: [
					new Choice({
						value: [
							new NumericString(),
							new PrintableString()
						]
					})
				]
			}),
			new Constructed({
				optional: true,
				idBlock: {
					tagClass: 2, // APPLICATION-SPECIFIC
					tagNumber: 2 // [2]
				},
				name: (names.administration_domain_name || ""),
				value: [
					new Choice({
						value: [
							new NumericString(),
							new PrintableString()
						]
					})
				]
			}),
			new Primitive({
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 0 // [0]
				},
				name: (names.network_address || ""),
				isHexOnly: true
			}),
			new Primitive({
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 1 // [1]
				},
				name: (names.terminal_identifier || ""),
				isHexOnly: true
			}),
			new Constructed({
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 2 // [2]
				},
				name: (names.private_domain_name || ""),
				value: [
					new Choice({
						value: [
							new NumericString(),
							new PrintableString()
						]
					})
				]
			}),
			new Primitive({
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 3 // [3]
				},
				name: (names.organization_name || ""),
				isHexOnly: true
			}),
			new Primitive({
				optional: true,
				name: (names.numeric_user_identifier || ""),
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 4 // [4]
				},
				isHexOnly: true
			}),
			new Constructed({
				optional: true,
				name: (names.personal_name || ""),
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 5 // [5]
				},
				value: [
					new Primitive({
						idBlock: {
							tagClass: 3, // CONTEXT-SPECIFIC
							tagNumber: 0 // [0]
						},
						isHexOnly: true
					}),
					new Primitive({
						optional: true,
						idBlock: {
							tagClass: 3, // CONTEXT-SPECIFIC
							tagNumber: 1 // [1]
						},
						isHexOnly: true
					}),
					new Primitive({
						optional: true,
						idBlock: {
							tagClass: 3, // CONTEXT-SPECIFIC
							tagNumber: 2 // [2]
						},
						isHexOnly: true
					}),
					new Primitive({
						optional: true,
						idBlock: {
							tagClass: 3, // CONTEXT-SPECIFIC
							tagNumber: 3 // [3]
						},
						isHexOnly: true
					})
				]
			}),
			new Constructed({
				optional: true,
				name: (names.organizational_unit_names || ""),
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 6 // [6]
				},
				value: [
					new Repeated({
						value: new PrintableString()
					})
				]
			})
		]
	}));
}
//**************************************************************************************
/**
 * Schema for "builtInDomainDefinedAttributes" of "ORAddress"
 * @param {boolean} optional
 * @returns {Sequence}
 */
function builtInDomainDefinedAttributes(optional = false)
{
	return (new Sequence({
		optional,
		value: [
			new PrintableString(),
			new PrintableString()
		]
	}));
}
//**************************************************************************************
/**
 * Schema for "builtInDomainDefinedAttributes" of "ORAddress"
 * @param {boolean} optional
 * @returns {Set}
 */
function extensionAttributes(optional = false)
{
	return (new Set({
		optional,
		value: [
			new Primitive({
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 0 // [0]
				},
				isHexOnly: true
			}),
			new Constructed({
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 1 // [1]
				},
				value: [new Any()]
			})
		]
	}));
}
//**************************************************************************************
//endregion
//**************************************************************************************
/**
 * Class from RFC5280
 */
class GeneralName
{
	//**********************************************************************************
	/**
	 * Constructor for GeneralName class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 * @property {number} [type] value type - from a tagged value (0 for "otherName", 1 for "rfc822Name" etc.)
	 * @property {Object} [value] asn1js object having GENERAL_NAME value (type depends on "type" value)
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {number}
		 * @description value type - from a tagged value (0 for "otherName", 1 for "rfc822Name" etc.)
		 */
		this.type = getParametersValue(parameters, "type", GeneralName.defaultValues("type"));
		/**
		 * @type {Object}
		 * @description asn1js object having GENERAL_NAME value (type depends on "type" value)
		 */
		this.value = getParametersValue(parameters, "value", GeneralName.defaultValues("value"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "type":
				return 9;
			case "value":
				return {};
			default:
				throw new Error(`Invalid member name for GeneralName class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Compare values with default values for all class members
	 * @param {string} memberName String name for a class member
	 * @param {*} memberValue Value to compare with default value
	 */
	static compareWithDefault(memberName, memberValue)
	{
		switch(memberName)
		{
			case "type":
				return (memberValue === GeneralName.defaultValues(memberName));
			case "value":
				return (Object.keys(memberValue).length === 0);
			default:
				throw new Error(`Invalid member name for GeneralName class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//GeneralName ::= Choice {
		//    otherName                       [0]     OtherName,
		//    rfc822Name                      [1]     IA5String,
		//    dNSName                         [2]     IA5String,
		//    x400Address                     [3]     ORAddress,
		//    directoryName                   [4]     value,
		//    ediPartyName                    [5]     EDIPartyName,
		//    uniformResourceIdentifier       [6]     IA5String,
		//    iPAddress                       [7]     OCTET STRING,
		//    registeredID                    [8]     OBJECT IDENTIFIER }

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {Object} [directoryName]
		 * @property {Object} [builtInStandardAttributes]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Choice({
			value: [
				new Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					name: (names.blockName || ""),
					value: [
						new ObjectIdentifier(),
						new Constructed({
							idBlock: {
								tagClass: 3, // CONTEXT-SPECIFIC
								tagNumber: 0 // [0]
							},
							value: [new Any()]
						})
					]
				}),
				new Primitive({
					name: (names.blockName || ""),
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					}
				}),
				new Primitive({
					name: (names.blockName || ""),
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 2 // [2]
					}
				}),
				new Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 3 // [3]
					},
					name: (names.blockName || ""),
					value: [
						builtInStandardAttributes((names.builtInStandardAttributes || {}), false),
						builtInDomainDefinedAttributes(true),
						extensionAttributes(true)
					]
				}),
				new Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 4 // [4]
					},
					name: (names.blockName || ""),
					value: [RelativeDistinguishedNames.schema(names.directoryName || {})]
				}),
				new Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 5 // [5]
					},
					name: (names.blockName || ""),
					value: [
						new Constructed({
							optional: true,
							idBlock: {
								tagClass: 3, // CONTEXT-SPECIFIC
								tagNumber: 0 // [0]
							},
							value: [
								new Choice({
									value: [
										new TeletexString(),
										new PrintableString(),
										new UniversalString(),
										new Utf8String(),
										new BmpString()
									]
								})
							]
						}),
						new Constructed({
							idBlock: {
								tagClass: 3, // CONTEXT-SPECIFIC
								tagNumber: 1 // [1]
							},
							value: [
								new Choice({
									value: [
										new TeletexString(),
										new PrintableString(),
										new UniversalString(),
										new Utf8String(),
										new BmpString()
									]
								})
							]
						})
					]
				}),
				new Primitive({
					name: (names.blockName || ""),
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 6 // [6]
					}
				}),
				new Primitive({
					name: (names.blockName || ""),
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 7 // [7]
					}
				}),
				new Primitive({
					name: (names.blockName || ""),
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 8 // [8]
					}
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			GeneralName.schema({
				names: {
					blockName: "blockName",
					otherName: "otherName",
					rfc822Name: "rfc822Name",
					dNSName: "dNSName",
					x400Address: "x400Address",
					directoryName: {
						names: {
							blockName: "directoryName"
						}
					},
					ediPartyName: "ediPartyName",
					uniformResourceIdentifier: "uniformResourceIdentifier",
					iPAddress: "iPAddress",
					registeredID: "registeredID"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for GENERAL_NAME");
		//endregion

		//region Get internal properties from parsed schema
		this.type = asn1.result.blockName.idBlock.tagNumber;

		switch(this.type)
		{
			case 0: // otherName
				this.value = asn1.result.blockName;
				break;
			case 1: // rfc822Name + dNSName + uniformResourceIdentifier
			case 2:
			case 6:
				{
					const value = asn1.result.blockName;

					value.idBlock.tagClass = 1; // UNIVERSAL
					value.idBlock.tagNumber = 22; // IA5STRING

					const valueBER = value.toBER(false);

					this.value = fromBER(valueBER).result.valueBlock.value;
				}
				break;
			case 3: // x400Address
				this.value = asn1.result.blockName;
				break;
			case 4: // directoryName
				this.value = new RelativeDistinguishedNames({ schema: asn1.result.directoryName });
				break;
			case 5: // ediPartyName
				this.value = asn1.result.ediPartyName;
				break;
			case 7: // iPAddress
				this.value = new OctetString({ valueHex: asn1.result.blockName.valueBlock.valueHex });
				break;
			case 8: // registeredID
				{
					const value = asn1.result.blockName;

					value.idBlock.tagClass = 1; // UNIVERSAL
					value.idBlock.tagNumber = 6; // ObjectIdentifier

					const valueBER = value.toBER(false);

					this.value = fromBER(valueBER).result.valueBlock.toString(); // Getting a string representation of the ObjectIdentifier
				}
				break;
			default:
		}
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		switch(this.type)
		{
			case 0:
			case 3:
			case 5:
				return new Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: this.type
					},
					value: [
						this.value
					]
				});
			case 1:
			case 2:
			case 6:
				{
					const value = new IA5String({ value: this.value });

					value.idBlock.tagClass = 3;
					value.idBlock.tagNumber = this.type;

					return value;
				}
			case 4:
				return new Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 4
					},
					value: [this.value.toSchema()]
				});
			case 7:
				{
					const value = this.value;

					value.idBlock.tagClass = 3;
					value.idBlock.tagNumber = this.type;

					return value;
				}
			case 8:
				{
					const value = new ObjectIdentifier({ value: this.value });

					value.idBlock.tagClass = 3;
					value.idBlock.tagNumber = this.type;

					return value;
				}
			default:
				return GeneralName.schema();
		}
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		const _object = {
			type: this.type
		};

		if((typeof this.value) === "string")
			_object.value = this.value;
		else
			_object.value = this.value.toJSON();

		return _object;
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class AccessDescription
{
	//**********************************************************************************
	/**
	 * Constructor for AccessDescription class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {string}
		 * @description accessMethod
		 */
		this.accessMethod = getParametersValue(parameters, "accessMethod", AccessDescription.defaultValues("accessMethod"));
		/**
		 * @type {GeneralName}
		 * @description accessLocation
		 */
		this.accessLocation = getParametersValue(parameters, "accessLocation", AccessDescription.defaultValues("accessLocation"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "accessMethod":
				return "";
			case "accessLocation":
				return new GeneralName();
			default:
				throw new Error(`Invalid member name for AccessDescription class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//AccessDescription  ::=  SEQUENCE {
		//    accessMethod          OBJECT IDENTIFIER,
		//    accessLocation        GeneralName  }

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [accessMethod]
		 * @property {string} [accessLocation]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new ObjectIdentifier({ name: (names.accessMethod || "") }),
				GeneralName.schema(names.accessLocation || {})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			AccessDescription.schema({
				names: {
					accessMethod: "accessMethod",
					accessLocation: {
						names: {
							blockName: "accessLocation"
						}
					}
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for AccessDescription");
		//endregion

		//region Get internal properties from parsed schema
		this.accessMethod = asn1.result.accessMethod.valueBlock.toString();
		this.accessLocation = new GeneralName({ schema: asn1.result.accessLocation });
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: [
				new ObjectIdentifier({ value: this.accessMethod }),
				this.accessLocation.toSchema()
			]
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		return {
			accessMethod: this.accessMethod,
			accessLocation: this.accessLocation.toJSON()
		};
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class AltName
{
	//**********************************************************************************
	/**
	 * Constructor for AltName class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Array.<GeneralName>}
		 * @description type
		 */
		this.altNames = getParametersValue(parameters, "altNames", AltName.defaultValues("altNames"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "altNames":
				return [];
			default:
				throw new Error(`Invalid member name for AltName class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		// SubjectAltName OID ::= 2.5.29.17
		// IssuerAltName OID ::= 2.5.29.18
		//
		// AltName ::= GeneralNames

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [altNames]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Repeated({
					name: (names.altNames || ""),
					value: GeneralName.schema()
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			AltName.schema({
				names: {
					altNames: "altNames"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for AltName");
		//endregion

		//region Get internal properties from parsed schema
		if("altNames" in asn1.result)
			this.altNames = Array.from(asn1.result.altNames, element => new GeneralName({ schema: element }));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: Array.from(this.altNames, element => element.toSchema())
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		return {
			altNames: Array.from(this.altNames, element => element.toJSON())
		};
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class Time
{
	//**********************************************************************************
	/**
	 * Constructor for Time class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 * @property {number} [type] 0 - UTCTime; 1 - GeneralizedTime; 2 - empty value
	 * @property {Date} [value] Value of the TIME class
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {number}
		 * @description 0 - UTCTime; 1 - GeneralizedTime; 2 - empty value
		 */
		this.type = getParametersValue(parameters, "type", Time.defaultValues("type"));
		/**
		 * @type {Date}
		 * @description Value of the TIME class
		 */
		this.value = getParametersValue(parameters, "value", Time.defaultValues("value"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "type":
				return 0;
			case "value":
				return new Date(0, 0, 0);
			default:
				throw new Error(`Invalid member name for Time class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @param {boolean} optional Flag that current schema should be optional
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {}, optional = false)
	{
		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [utcTimeName] Name for "utcTimeName" choice
		 * @property {string} [generalTimeName] Name for "generalTimeName" choice
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Choice({
			optional,
			value: [
				new UTCTime({ name: (names.utcTimeName || "") }),
				new GeneralizedTime({ name: (names.generalTimeName || "") })
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema, schema, Time.schema({
			names: {
				utcTimeName: "utcTimeName",
				generalTimeName: "generalTimeName"
			}
		}));

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for TIME");
		//endregion

		//region Get internal properties from parsed schema
		if("utcTimeName" in asn1.result)
		{
			this.type = 0;
			this.value = asn1.result.utcTimeName.toDate();
		}
		if("generalTimeName" in asn1.result)
		{
			this.type = 1;
			this.value = asn1.result.generalTimeName.toDate();
		}
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		let result = {};

		if(this.type === 0)
			result = new UTCTime({ valueDate: this.value });
		if(this.type === 1)
			result = new GeneralizedTime({ valueDate: this.value });

		return result;
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		return {
			type: this.type,
			value: this.value
		};
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class SubjectDirectoryAttributes
{
	//**********************************************************************************
	/**
	 * Constructor for SubjectDirectoryAttributes class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Array.<Attribute>}
		 * @description attributes
		 */
		this.attributes = getParametersValue(parameters, "attributes", SubjectDirectoryAttributes.defaultValues("attributes"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "attributes":
				return [];
			default:
				throw new Error(`Invalid member name for SubjectDirectoryAttributes class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		// SubjectDirectoryAttributes OID ::= 2.5.29.9
		//
		//SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [utcTimeName] Name for "utcTimeName" choice
		 * @property {string} [generalTimeName] Name for "generalTimeName" choice
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Repeated({
					name: (names.attributes || ""),
					value: Attribute.schema()
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			SubjectDirectoryAttributes.schema({
				names: {
					attributes: "attributes"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for SubjectDirectoryAttributes");
		//endregion

		//region Get internal properties from parsed schema
		this.attributes = Array.from(asn1.result.attributes, element => new Attribute({ schema: element }));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: Array.from(this.attributes, element => element.toSchema())
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		return {
			attributes: Array.from(this.attributes, element => element.toJSON())
		};
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class PrivateKeyUsagePeriod
{
	//**********************************************************************************
	/**
	 * Constructor for PrivateKeyUsagePeriod class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		if("notBefore" in parameters)
			/**
			 * @type {Date}
			 * @description notBefore
			 */
			this.notBefore = getParametersValue(parameters, "notBefore", PrivateKeyUsagePeriod.defaultValues("notBefore"));

		if("notAfter" in parameters)
			/**
			 * @type {Date}
			 * @description notAfter
			 */
			this.notAfter = getParametersValue(parameters, "notAfter", PrivateKeyUsagePeriod.defaultValues("notAfter"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "notBefore":
				return new Date();
			case "notAfter":
				return new Date();
			default:
				throw new Error(`Invalid member name for PrivateKeyUsagePeriod class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		// PrivateKeyUsagePeriod OID ::= 2.5.29.16
		//
		//PrivateKeyUsagePeriod ::= SEQUENCE {
		//    notBefore       [0]     GeneralizedTime OPTIONAL,
		//    notAfter        [1]     GeneralizedTime OPTIONAL }
		//-- either notBefore or notAfter MUST be present

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [notBefore]
		 * @property {string} [notAfter]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Primitive({
					name: (names.notBefore || ""),
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					}
				}),
				new Primitive({
					name: (names.notAfter || ""),
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					}
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			PrivateKeyUsagePeriod.schema({
				names: {
					notBefore: "notBefore",
					notAfter: "notAfter"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for PrivateKeyUsagePeriod");
		//endregion

		//region Get internal properties from parsed schema
		if("notBefore" in asn1.result)
		{
			const localNotBefore = new GeneralizedTime();
			localNotBefore.fromBuffer(asn1.result.notBefore.valueBlock.valueHex);
			this.notBefore = localNotBefore.toDate();
		}

		if("notAfter" in asn1.result)
		{
			const localNotAfter = new GeneralizedTime({ valueHex: asn1.result.notAfter.valueBlock.valueHex });
			localNotAfter.fromBuffer(asn1.result.notAfter.valueBlock.valueHex);
			this.notAfter = localNotAfter.toDate();
		}
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Create array for output sequence
		const outputArray = [];
		
		if("notBefore" in this)
		{
			outputArray.push(new Primitive({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 0 // [0]
				},
				valueHex: (new GeneralizedTime({ valueDate: this.notBefore })).valueBlock.valueHex
			}));
		}
		
		if("notAfter" in this)
		{
			outputArray.push(new Primitive({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 1 // [1]
				},
				valueHex: (new GeneralizedTime({ valueDate: this.notAfter })).valueBlock.valueHex
			}));
		}
		//endregion
		
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: outputArray
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		const object = {};

		if("notBefore" in this)
			object.notBefore = this.notBefore;

		if("notAfter" in this)
			object.notAfter = this.notAfter;

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class BasicConstraints
{
	//**********************************************************************************
	/**
	 * Constructor for BasicConstraints class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 * @property {Object} [cA]
	 * @property {Object} [pathLenConstraint]
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {boolean}
		 * @description cA
		 */
		this.cA = getParametersValue(parameters, "cA", false);

		if("pathLenConstraint" in parameters)
			/**
			 * @type {number|Integer}
			 * @description pathLenConstraint
			 */
			this.pathLenConstraint = getParametersValue(parameters, "pathLenConstraint", 0);
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "cA":
				return false;
			default:
				throw new Error(`Invalid member name for BasicConstraints class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		// BasicConstraints OID ::= 2.5.29.19
		//
		//BasicConstraints ::= SEQUENCE {
		//    cA                      BOOLEAN DEFAULT FALSE,
		//    pathLenConstraint       INTEGER (0..MAX) OPTIONAL }

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [cA]
		 * @property {string} [pathLenConstraint]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Boolean({
					optional: true,
					name: (names.cA || "")
				}),
				new Integer({
					optional: true,
					name: (names.pathLenConstraint || "")
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			BasicConstraints.schema({
				names: {
					cA: "cA",
					pathLenConstraint: "pathLenConstraint"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for BasicConstraints");
		//endregion

		//region Get internal properties from parsed schema
		if("cA" in asn1.result)
			this.cA = asn1.result.cA.valueBlock.value;

		if("pathLenConstraint" in asn1.result)
		{
			if(asn1.result.pathLenConstraint.valueBlock.isHexOnly)
				this.pathLenConstraint = asn1.result.pathLenConstraint;
			else
				this.pathLenConstraint = asn1.result.pathLenConstraint.valueBlock.valueDec;
		}
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Create array for output sequence
		const outputArray = [];
		
		if(this.cA !== BasicConstraints.defaultValues("cA"))
			outputArray.push(new Boolean({ value: this.cA }));
		
		if("pathLenConstraint" in this)
		{
			if(this.pathLenConstraint instanceof Integer)
				outputArray.push(this.pathLenConstraint);
			else
				outputArray.push(new Integer({ value: this.pathLenConstraint }));
		}
		//endregion
		
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: outputArray
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		const object = {};

		if(this.cA !== BasicConstraints.defaultValues("cA"))
			object.cA = this.cA;

		if("pathLenConstraint" in this)
		{
			if(this.pathLenConstraint instanceof Integer)
				object.pathLenConstraint = this.pathLenConstraint.toJSON();
			else
				object.pathLenConstraint = this.pathLenConstraint;
		}

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class IssuingDistributionPoint
{
	//**********************************************************************************
	/**
	 * Constructor for IssuingDistributionPoint class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		if("distributionPoint" in parameters)
			/**
			 * @type {Array.<GeneralName>|RelativeDistinguishedNames}
			 * @description distributionPoint
			 */
			this.distributionPoint = getParametersValue(parameters, "distributionPoint", IssuingDistributionPoint.defaultValues("distributionPoint"));

		/**
		 * @type {boolean}
		 * @description onlyContainsUserCerts
		 */
		this.onlyContainsUserCerts = getParametersValue(parameters, "onlyContainsUserCerts", IssuingDistributionPoint.defaultValues("onlyContainsUserCerts"));

		/**
		 * @type {boolean}
		 * @description onlyContainsCACerts
		 */
		this.onlyContainsCACerts = getParametersValue(parameters, "onlyContainsCACerts", IssuingDistributionPoint.defaultValues("onlyContainsCACerts"));

		if("onlySomeReasons" in parameters)
			/**
			 * @type {number}
			 * @description onlySomeReasons
			 */
			this.onlySomeReasons = getParametersValue(parameters, "onlySomeReasons", IssuingDistributionPoint.defaultValues("onlySomeReasons"));

		/**
		 * @type {boolean}
		 * @description indirectCRL
		 */
		this.indirectCRL = getParametersValue(parameters, "indirectCRL", IssuingDistributionPoint.defaultValues("indirectCRL"));

		/**
		 * @type {boolean}
		 * @description onlyContainsAttributeCerts
		 */
		this.onlyContainsAttributeCerts = getParametersValue(parameters, "onlyContainsAttributeCerts", IssuingDistributionPoint.defaultValues("onlyContainsAttributeCerts"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "distributionPoint":
				return [];
			case "onlyContainsUserCerts":
				return false;
			case "onlyContainsCACerts":
				return false;
			case "onlySomeReasons":
				return 0;
			case "indirectCRL":
				return false;
			case "onlyContainsAttributeCerts":
				return false;
			default:
				throw new Error(`Invalid member name for IssuingDistributionPoint class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		// IssuingDistributionPoint OID ::= 2.5.29.28
		//
		//IssuingDistributionPoint ::= SEQUENCE {
		//    distributionPoint          [0] DistributionPointName OPTIONAL,
		//    onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
		//    onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
		//    onlySomeReasons            [3] ReasonFlags OPTIONAL,
		//    indirectCRL                [4] BOOLEAN DEFAULT FALSE,
		//    onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
		//
		//ReasonFlags ::= BIT STRING {
		//    unused                  (0),
		//    keyCompromise           (1),
		//    cACompromise            (2),
		//    affiliationChanged      (3),
		//    superseded              (4),
		//    cessationOfOperation    (5),
		//    certificateHold         (6),
		//    privilegeWithdrawn      (7),
		//    aACompromise            (8) }
		
		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [distributionPoint]
		 * @property {string} [distributionPointNames]
		 * @property {string} [onlyContainsUserCerts]
		 * @property {string} [onlyContainsCACerts]
		 * @property {string} [onlySomeReasons]
		 * @property {string} [indirectCRL]
		 * @property {string} [onlyContainsAttributeCerts]
		 */
		const names = getParametersValue(parameters, "names", {});
		
		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [
						new Choice({
							value: [
								new Constructed({
									name: (names.distributionPoint || ""),
									idBlock: {
										tagClass: 3, // CONTEXT-SPECIFIC
										tagNumber: 0 // [0]
									},
									value: [
										new Repeated({
											name: (names.distributionPointNames || ""),
											value: GeneralName.schema()
										})
									]
								}),
								new Constructed({
									name: (names.distributionPoint || ""),
									idBlock: {
										tagClass: 3, // CONTEXT-SPECIFIC
										tagNumber: 1 // [1]
									},
									value: RelativeDistinguishedNames.schema().valueBlock.value
								})
							]
						})
					]
				}),
				new Primitive({
					name: (names.onlyContainsUserCerts || ""),
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					}
				}), // IMPLICIT boolean value
				new Primitive({
					name: (names.onlyContainsCACerts || ""),
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 2 // [2]
					}
				}), // IMPLICIT boolean value
				new Primitive({
					name: (names.onlySomeReasons || ""),
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 3 // [3]
					}
				}), // IMPLICIT bitstring value
				new Primitive({
					name: (names.indirectCRL || ""),
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 4 // [4]
					}
				}), // IMPLICIT boolean value
				new Primitive({
					name: (names.onlyContainsAttributeCerts || ""),
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 5 // [5]
					}
				}) // IMPLICIT boolean value
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			IssuingDistributionPoint.schema({
				names: {
					distributionPoint: "distributionPoint",
					distributionPointNames: "distributionPointNames",
					onlyContainsUserCerts: "onlyContainsUserCerts",
					onlyContainsCACerts: "onlyContainsCACerts",
					onlySomeReasons: "onlySomeReasons",
					indirectCRL: "indirectCRL",
					onlyContainsAttributeCerts: "onlyContainsAttributeCerts"
				}
			})
		);
		
		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for IssuingDistributionPoint");
		//endregion
		
		//region Get internal properties from parsed schema
		if("distributionPoint" in asn1.result)
		{
			switch(true)
			{
				case (asn1.result.distributionPoint.idBlock.tagNumber === 0): // GENERAL_NAMES variant
					this.distributionPoint = Array.from(asn1.result.distributionPointNames, element => new GeneralName({ schema: element }));
					break;
				case (asn1.result.distributionPoint.idBlock.tagNumber === 1): // RDN variant
					{
						asn1.result.distributionPoint.idBlock.tagClass = 1; // UNIVERSAL
						asn1.result.distributionPoint.idBlock.tagNumber = 16; // SEQUENCE

						this.distributionPoint = new RelativeDistinguishedNames({ schema: asn1.result.distributionPoint });
					}
					break;
				default:
					throw new Error("Unknown tagNumber for distributionPoint: {$asn1.result.distributionPoint.idBlock.tagNumber}");
			}
		}
		
		if("onlyContainsUserCerts" in asn1.result)
		{
			const view = new Uint8Array(asn1.result.onlyContainsUserCerts.valueBlock.valueHex);
			this.onlyContainsUserCerts = (view[0] !== 0x00);
		}
		
		if("onlyContainsCACerts" in asn1.result)
		{
			const view = new Uint8Array(asn1.result.onlyContainsCACerts.valueBlock.valueHex);
			this.onlyContainsCACerts = (view[0] !== 0x00);
		}
		
		if("onlySomeReasons" in asn1.result)
		{
			const view = new Uint8Array(asn1.result.onlySomeReasons.valueBlock.valueHex);
			this.onlySomeReasons = view[0];
		}
		
		if("indirectCRL" in asn1.result)
		{
			const view = new Uint8Array(asn1.result.indirectCRL.valueBlock.valueHex);
			this.indirectCRL = (view[0] !== 0x00);
		}
		
		if("onlyContainsAttributeCerts" in asn1.result)
		{
			const view = new Uint8Array(asn1.result.onlyContainsAttributeCerts.valueBlock.valueHex);
			this.onlyContainsAttributeCerts = (view[0] !== 0x00);
		}
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Create array for output sequence
		const outputArray = [];
		
		if("distributionPoint" in this)
		{
			let value;
			
			if(this.distributionPoint instanceof Array)
			{
				value = new Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: Array.from(this.distributionPoint, element => element.toSchema())
				});
			}
			else
			{
				value = this.distributionPoint.toSchema();
				
				value.idBlock.tagClass = 3; // CONTEXT - SPECIFIC
				value.idBlock.tagNumber = 1; // [1]
			}
			
			outputArray.push(value);
		}
		
		if(this.onlyContainsUserCerts !== IssuingDistributionPoint.defaultValues("onlyContainsUserCerts"))
		{
			outputArray.push(new Primitive({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 1 // [1]
				},
				valueHex: (new Uint8Array([0xFF])).buffer
			}));
		}
		
		if(this.onlyContainsCACerts !== IssuingDistributionPoint.defaultValues("onlyContainsCACerts"))
		{
			outputArray.push(new Primitive({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 2 // [2]
				},
				valueHex: (new Uint8Array([0xFF])).buffer
			}));
		}
		
		if("onlySomeReasons" in this)
		{
			const buffer = new ArrayBuffer(1);
			const view = new Uint8Array(buffer);
			
			view[0] = this.onlySomeReasons;
			
			outputArray.push(new Primitive({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 3 // [3]
				},
				valueHex: buffer
			}));
		}
		
		if(this.indirectCRL !== IssuingDistributionPoint.defaultValues("indirectCRL"))
		{
			outputArray.push(new Primitive({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 4 // [4]
				},
				valueHex: (new Uint8Array([0xFF])).buffer
			}));
		}
		
		if(this.onlyContainsAttributeCerts !== IssuingDistributionPoint.defaultValues("onlyContainsAttributeCerts"))
		{
			outputArray.push(new Primitive({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 5 // [5]
				},
				valueHex: (new Uint8Array([0xFF])).buffer
			}));
		}
		//endregion
		
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: outputArray
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		const object = {};
		
		if("distributionPoint" in this)
		{
			if(this.distributionPoint instanceof Array)
				object.distributionPoint = Array.from(this.distributionPoint, element => element.toJSON());
			else
				object.distributionPoint = this.distributionPoint.toJSON();
		}
		
		if(this.onlyContainsUserCerts !== IssuingDistributionPoint.defaultValues("onlyContainsUserCerts"))
			object.onlyContainsUserCerts = this.onlyContainsUserCerts;
		
		if(this.onlyContainsCACerts !== IssuingDistributionPoint.defaultValues("onlyContainsCACerts"))
			object.onlyContainsCACerts = this.onlyContainsCACerts;
		
		if("onlySomeReasons" in this)
			object.onlySomeReasons = this.onlySomeReasons;
		
		if(this.indirectCRL !== IssuingDistributionPoint.defaultValues("indirectCRL"))
			object.indirectCRL = this.indirectCRL;
		
		if(this.onlyContainsAttributeCerts !== IssuingDistributionPoint.defaultValues("onlyContainsAttributeCerts"))
			object.onlyContainsAttributeCerts = this.onlyContainsAttributeCerts;
		
		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class GeneralNames
{
	//**********************************************************************************
	/**
	 * Constructor for GeneralNames class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Array.<GeneralName>}
		 * @description Array of "general names"
		 */
		this.names = getParametersValue(parameters, "names", GeneralNames.defaultValues("names"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "names":
				return [];
			default:
				throw new Error(`Invalid member name for GeneralNames class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @param {boolean} [optional=false] Flag would be element optional or not
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {}, optional = false)
	{
		/**
		 * @type {Object}
		 * @property {string} utcTimeName Name for "utcTimeName" choice
		 * @property {string} generalTimeName Name for "generalTimeName" choice
		 */
		const names = getParametersValue(parameters, "names", {});
		
		return (new Sequence({
			optional,
			name: (names.blockName || ""),
			value: [
				new Repeated({
					name: (names.generalNames || ""),
					value: GeneralName.schema()
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			GeneralNames.schema({
				names: {
					blockName: "names",
					generalNames: "generalNames"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for GeneralNames");
		//endregion

		//region Get internal properties from parsed schema
		this.names = Array.from(asn1.result.generalNames, element => new GeneralName({ schema: element }));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: Array.from(this.names, element => element.toSchema())
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		return {
			names: Array.from(this.names, element => element.toJSON())
		};
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class GeneralSubtree
{
	//**********************************************************************************
	/**
	 * Constructor for GeneralSubtree class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {GeneralName}
		 * @description base
		 */
		this.base = getParametersValue(parameters, "base", GeneralSubtree.defaultValues("base"));

		/**
		 * @type {number|Integer}
		 * @description base
		 */
		this.minimum = getParametersValue(parameters, "minimum", GeneralSubtree.defaultValues("minimum"));

		if("maximum" in parameters)
			/**
			 * @type {number|Integer}
			 * @description minimum
			 */
			this.maximum = getParametersValue(parameters, "maximum", GeneralSubtree.defaultValues("maximum"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "base":
				return new GeneralName();
			case "minimum":
				return 0;
			case "maximum":
				return 0;
			default:
				throw new Error(`Invalid member name for GeneralSubtree class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//GeneralSubtree ::= SEQUENCE {
		//    base                    GeneralName,
		//    minimum         [0]     BaseDistance DEFAULT 0,
		//    maximum         [1]     BaseDistance OPTIONAL }
		//
		//BaseDistance ::= INTEGER (0..MAX)

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [base]
		 * @property {string} [minimum]
		 * @property {string} [maximum]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				GeneralName.schema(names.base || {}),
				new Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [new Integer({ name: (names.minimum || "") })]
				}),
				new Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					value: [new Integer({ name: (names.maximum || "") })]
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			GeneralSubtree.schema({
				names: {
					base: {
						names: {
							blockName: "base"
						}
					},
					minimum: "minimum",
					maximum: "maximum"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for ");
		//endregion

		//region Get internal properties from parsed schema
		this.base = new GeneralName({ schema: asn1.result.base });

		if("minimum" in asn1.result)
		{
			if(asn1.result.minimum.valueBlock.isHexOnly)
				this.minimum = asn1.result.minimum;
			else
				this.minimum = asn1.result.minimum.valueBlock.valueDec;
		}

		if("maximum" in asn1.result)
		{
			if(asn1.result.maximum.valueBlock.isHexOnly)
				this.maximum = asn1.result.maximum;
			else
				this.maximum = asn1.result.maximum.valueBlock.valueDec;
		}
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Create array for output sequence
		const outputArray = [];
		
		outputArray.push(this.base.toSchema());
		
		if(this.minimum !== 0)
		{
			let valueMinimum = 0;
			
			if(this.minimum instanceof Integer)
				valueMinimum = this.minimum;
			else
				valueMinimum = new Integer({ value: this.minimum });
			
			outputArray.push(new Constructed({
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 0 // [0]
				},
				value: [valueMinimum]
			}));
		}
		
		if("maximum" in this)
		{
			let valueMaximum = 0;
			
			if(this.maximum instanceof Integer)
				valueMaximum = this.maximum;
			else
				valueMaximum = new Integer({ value: this.maximum });
			
			outputArray.push(new Constructed({
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 1 // [1]
				},
				value: [valueMaximum]
			}));
		}
		//endregion
		
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: outputArray
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		const object = {
			base: this.base.toJSON()
		};
		
		if(this.minimum !== 0)
		{
			if((typeof this.minimum) === "number")
				object.minimum = this.minimum;
			else
				object.minimum = this.minimum.toJSON();
		}
		
		if("maximum" in this)
		{
			if((typeof this.maximum) === "number")
				object.maximum = this.maximum;
			else
				object.maximum = this.maximum.toJSON();
		}
		
		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class NameConstraints
{
	//**********************************************************************************
	/**
	 * Constructor for NameConstraints class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		if("permittedSubtrees" in parameters)
			/**
			 * @type {Array.<GeneralSubtree>}
			 * @description permittedSubtrees
			 */
			this.permittedSubtrees = getParametersValue(parameters, "permittedSubtrees", NameConstraints.defaultValues("permittedSubtrees"));

		if("excludedSubtrees" in parameters)
			/**
			 * @type {Array.<GeneralSubtree>}
			 * @description excludedSubtrees
			 */
			this.excludedSubtrees = getParametersValue(parameters, "excludedSubtrees", NameConstraints.defaultValues("excludedSubtrees"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "permittedSubtrees":
				return [];
			case "excludedSubtrees":
				return [];
			default:
				throw new Error(`Invalid member name for NameConstraints class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		// NameConstraints OID ::= 2.5.29.30
		//
		//NameConstraints ::= SEQUENCE {
		//    permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
		//    excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [permittedSubtrees]
		 * @property {string} [excludedSubtrees]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [
						new Repeated({
							name: (names.permittedSubtrees || ""),
							value: GeneralSubtree.schema()
						})
					]
				}),
				new Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					value: [
						new Repeated({
							name: (names.excludedSubtrees || ""),
							value: GeneralSubtree.schema()
						})
					]
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			NameConstraints.schema({
				names: {
					permittedSubtrees: "permittedSubtrees",
					excludedSubtrees: "excludedSubtrees"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for NameConstraints");
		//endregion

		//region Get internal properties from parsed schema
		if("permittedSubtrees" in asn1.result)
			this.permittedSubtrees = Array.from(asn1.result.permittedSubtrees, element => new GeneralSubtree({ schema: element }));

		if("excludedSubtrees" in asn1.result)
			this.excludedSubtrees = Array.from(asn1.result.excludedSubtrees, element => new GeneralSubtree({ schema: element }));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Create array for output sequence
		const outputArray = [];
		
		if("permittedSubtrees" in this)
		{
			outputArray.push(new Constructed({
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 0 // [0]
				},
				value: [new Sequence({
					value: Array.from(this.permittedSubtrees, element => element.toSchema())
				})]
			}));
		}
		
		if("excludedSubtrees" in this)
		{
			outputArray.push(new Constructed({
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 1 // [1]
				},
				value: [new Sequence({
					value: Array.from(this.excludedSubtrees, element => element.toSchema())
				})]
			}));
		}
		//endregion
		
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: outputArray
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		const object = {};
		
		if("permittedSubtrees" in this)
			object.permittedSubtrees = Array.from(this.permittedSubtrees, element => element.toJSON());

		if("excludedSubtrees" in this)
			object.excludedSubtrees = Array.from(this.excludedSubtrees, element => element.toJSON());

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class DistributionPoint
{
	//**********************************************************************************
	/**
	 * Constructor for DistributionPoint class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 * @property {Object} [distributionPoint]
	 * @property {Object} [reasons]
	 * @property {Object} [cRLIssuer]
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		if("distributionPoint" in parameters)
			/**
			 * @type {Array.<GeneralName>}
			 * @description distributionPoint
			 */
			this.distributionPoint = getParametersValue(parameters, "distributionPoint", DistributionPoint.defaultValues("distributionPoint"));

		if("reasons" in parameters)
			/**
			 * @type {BitString}
			 * @description values
			 */
			this.reasons = getParametersValue(parameters, "reasons", DistributionPoint.defaultValues("reasons"));

		if("cRLIssuer" in parameters)
			/**
			 * @type {Array.<GeneralName>}
			 * @description cRLIssuer
			 */
			this.cRLIssuer = getParametersValue(parameters, "cRLIssuer", DistributionPoint.defaultValues("cRLIssuer"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "distributionPoint":
				return [];
			case "reasons":
				return new BitString();
			case "cRLIssuer":
				return [];
			default:
				throw new Error(`Invalid member name for DistributionPoint class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//DistributionPoint ::= SEQUENCE {
		//    distributionPoint       [0]     DistributionPointName OPTIONAL,
		//    reasons                 [1]     ReasonFlags OPTIONAL,
		//    cRLIssuer               [2]     GeneralNames OPTIONAL }
		//
		//DistributionPointName ::= CHOICE {
		//    fullName                [0]     GeneralNames,
		//    nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
		//
		//ReasonFlags ::= BIT STRING {
		//    unused                  (0),
		//    keyCompromise           (1),
		//    cACompromise            (2),
		//    affiliationChanged      (3),
		//    superseded              (4),
		//    cessationOfOperation    (5),
		//    certificateHold         (6),
		//    privilegeWithdrawn      (7),
		//    aACompromise            (8) }

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [distributionPoint]
		 * @property {string} [distributionPointNames]
		 * @property {string} [reasons]
		 * @property {string} [cRLIssuer]
		 * @property {string} [cRLIssuerNames]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [
						new Choice({
							value: [
								new Constructed({
									name: (names.distributionPoint || ""),
									optional: true,
									idBlock: {
										tagClass: 3, // CONTEXT-SPECIFIC
										tagNumber: 0 // [0]
									},
									value: [
										new Repeated({
											name: (names.distributionPointNames || ""),
											value: GeneralName.schema()
										})
									]
								}),
								new Constructed({
									name: (names.distributionPoint || ""),
									optional: true,
									idBlock: {
										tagClass: 3, // CONTEXT-SPECIFIC
										tagNumber: 1 // [1]
									},
									value: RelativeDistinguishedNames.schema().valueBlock.value
								})
							]
						})
					]
				}),
				new Primitive({
					name: (names.reasons || ""),
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					}
				}), // IMPLICIT bitstring value
				new Constructed({
					name: (names.cRLIssuer || ""),
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 2 // [2]
					},
					value: [
						new Repeated({
							name: (names.cRLIssuerNames || ""),
							value: GeneralName.schema()
						})
					]
				}) // IMPLICIT bitstring value
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			DistributionPoint.schema({
				names: {
					distributionPoint: "distributionPoint",
					distributionPointNames: "distributionPointNames",
					reasons: "reasons",
					cRLIssuer: "cRLIssuer",
					cRLIssuerNames: "cRLIssuerNames"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for DistributionPoint");
		//endregion

		//region Get internal properties from parsed schema
		if("distributionPoint" in asn1.result)
		{
			if(asn1.result.distributionPoint.idBlock.tagNumber === 0) // GENERAL_NAMES variant
				this.distributionPoint = Array.from(asn1.result.distributionPointNames, element => new GeneralName({ schema: element }));

			if(asn1.result.distributionPoint.idBlock.tagNumber === 1) // RDN variant
			{
				asn1.result.distributionPoint.idBlock.tagClass = 1; // UNIVERSAL
				asn1.result.distributionPoint.idBlock.tagNumber = 16; // SEQUENCE

				this.distributionPoint = new RelativeDistinguishedNames({ schema: asn1.result.distributionPoint });
			}
		}

		if("reasons" in asn1.result)
			this.reasons = new BitString({ valueHex: asn1.result.reasons.valueBlock.valueHex });

		if("cRLIssuer" in asn1.result)
			this.cRLIssuer = Array.from(asn1.result.cRLIssuerNames, element => new GeneralName({ schema: element }));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Create array for output sequence
		const outputArray = [];
		
		if("distributionPoint" in this)
		{
			let internalValue;
			
			if(this.distributionPoint instanceof Array)
			{
				internalValue = new Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: Array.from(this.distributionPoint, element => element.toSchema())
				});
			}
			else
			{
				internalValue = new Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					value: [this.distributionPoint.toSchema()]
				});
			}
			
			outputArray.push(new Constructed({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 0 // [0]
				},
				value: [internalValue]
			}));
		}
		
		if("reasons" in this)
		{
			outputArray.push(new Primitive({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 1 // [1]
				},
				valueHex: this.reasons.valueBlock.valueHex
			}));
		}
		
		if("cRLIssuer" in this)
		{
			outputArray.push(new Constructed({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 2 // [2]
				},
				value: Array.from(this.cRLIssuer, element => element.toSchema())
			}));
		}
		//endregion
		
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: outputArray
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		const object = {};

		if("distributionPoint" in this)
		{
			if(this.distributionPoint instanceof Array)
				object.distributionPoint = Array.from(this.distributionPoint, element => element.toJSON());
			else
				object.distributionPoint = this.distributionPoint.toJSON();
		}

		if("reasons" in this)
			object.reasons = this.reasons.toJSON();

		if("cRLIssuer" in this)
			object.cRLIssuer = Array.from(this.cRLIssuer, element => element.toJSON());

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class CRLDistributionPoints
{
	//**********************************************************************************
	/**
	 * Constructor for CRLDistributionPoints class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Array.<DistributionPoint>}
		 * @description distributionPoints
		 */
		this.distributionPoints = getParametersValue(parameters, "distributionPoints", CRLDistributionPoints.defaultValues("distributionPoints"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "distributionPoints":
				return [];
			default:
				throw new Error(`Invalid member name for CRLDistributionPoints class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		// CRLDistributionPoints OID ::= 2.5.29.31
		//
		//CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [distributionPoints]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Repeated({
					name: (names.distributionPoints || ""),
					value: DistributionPoint.schema()
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			CRLDistributionPoints.schema({
				names: {
					distributionPoints: "distributionPoints"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for CRLDistributionPoints");
		//endregion

		//region Get internal properties from parsed schema
		this.distributionPoints = Array.from(asn1.result.distributionPoints, element => new DistributionPoint({ schema: element }));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: Array.from(this.distributionPoints, element => element.toSchema())
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		return {
			distributionPoints: Array.from(this.distributionPoints, element => element.toJSON())
		};
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class PolicyQualifierInfo
{
	//**********************************************************************************
	/**
	 * Constructor for PolicyQualifierInfo class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {string}
		 * @description policyQualifierId
		 */
		this.policyQualifierId = getParametersValue(parameters, "policyQualifierId", PolicyQualifierInfo.defaultValues("policyQualifierId"));
		/**
		 * @type {Object}
		 * @description qualifier
		 */
		this.qualifier = getParametersValue(parameters, "qualifier", PolicyQualifierInfo.defaultValues("qualifier"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "policyQualifierId":
				return "";
			case "qualifier":
				return new Any();
			default:
				throw new Error(`Invalid member name for PolicyQualifierInfo class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//PolicyQualifierInfo ::= SEQUENCE {
		//    policyQualifierId  PolicyQualifierId,
		//    qualifier          ANY DEFINED BY policyQualifierId }
		//
		//id-qt          OBJECT IDENTIFIER ::=  { id-pkix 2 }
		//id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
		//id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }
		//
		//PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [policyQualifierId]
		 * @property {string} [qualifier]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new ObjectIdentifier({ name: (names.policyQualifierId || "") }),
				new Any({ name: (names.qualifier || "") })
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			PolicyQualifierInfo.schema({
				names: {
					policyQualifierId: "policyQualifierId",
					qualifier: "qualifier"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for PolicyQualifierInfo");
		//endregion

		//region Get internal properties from parsed schema
		this.policyQualifierId = asn1.result.policyQualifierId.valueBlock.toString();
		this.qualifier = asn1.result.qualifier;
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: [
				new ObjectIdentifier({ value: this.policyQualifierId }),
				this.qualifier
			]
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		return {
			policyQualifierId: this.policyQualifierId,
			qualifier: this.qualifier.toJSON()
		};
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class PolicyInformation
{
	//**********************************************************************************
	/**
	 * Constructor for PolicyInformation class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {string}
		 * @description policyIdentifier
		 */
		this.policyIdentifier = getParametersValue(parameters, "policyIdentifier", PolicyInformation.defaultValues("policyIdentifier"));

		if("policyQualifiers" in parameters)
			/**
			 * @type {Array.<PolicyQualifierInfo>}
			 * @description Value of the TIME class
			 */
			this.policyQualifiers = getParametersValue(parameters, "policyQualifiers", PolicyInformation.defaultValues("policyQualifiers"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "policyIdentifier":
				return "";
			case "policyQualifiers":
				return [];
			default:
				throw new Error(`Invalid member name for PolicyInformation class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//PolicyInformation ::= SEQUENCE {
		//    policyIdentifier   CertPolicyId,
		//    policyQualifiers   SEQUENCE SIZE (1..MAX) OF
		//    PolicyQualifierInfo OPTIONAL }
		//
		//CertPolicyId ::= OBJECT IDENTIFIER

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [policyIdentifier]
		 * @property {string} [policyQualifiers]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new ObjectIdentifier({ name: (names.policyIdentifier || "") }),
				new Sequence({
					optional: true,
					value: [
						new Repeated({
							name: (names.policyQualifiers || ""),
							value: PolicyQualifierInfo.schema()
						})
					]
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			PolicyInformation.schema({
				names: {
					policyIdentifier: "policyIdentifier",
					policyQualifiers: "policyQualifiers"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for PolicyInformation");
		//endregion

		//region Get internal properties from parsed schema
		this.policyIdentifier = asn1.result.policyIdentifier.valueBlock.toString();

		if("policyQualifiers" in asn1.result)
			this.policyQualifiers = Array.from(asn1.result.policyQualifiers, element => new PolicyQualifierInfo({ schema: element }));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Create array for output sequence
		const outputArray = [];
		
		outputArray.push(new ObjectIdentifier({ value: this.policyIdentifier }));
		
		if("policyQualifiers" in this)
		{
			outputArray.push(new Sequence({
				value: Array.from(this.policyQualifiers, element => element.toSchema())
			}));
		}
		//endregion
		
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: outputArray
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		const object = {
			policyIdentifier: this.policyIdentifier
		};

		if("policyQualifiers" in this)
			object.policyQualifiers = Array.from(this.policyQualifiers, element => element.toJSON());

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class CertificatePolicies
{
	//**********************************************************************************
	/**
	 * Constructor for CertificatePolicies class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Array.<PolicyInformation>}
		 * @description certificatePolicies
		 */
		this.certificatePolicies = getParametersValue(parameters, "certificatePolicies", CertificatePolicies.defaultValues("certificatePolicies"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "certificatePolicies":
				return [];
			default:
				throw new Error(`Invalid member name for CertificatePolicies class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		// CertificatePolicies OID ::= 2.5.29.32
		//
		//certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [certificatePolicies]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Repeated({
					name: (names.certificatePolicies || ""),
					value: PolicyInformation.schema()
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			CertificatePolicies.schema({
				names: {
					certificatePolicies: "certificatePolicies"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for CertificatePolicies");
		//endregion

		//region Get internal properties from parsed schema
		this.certificatePolicies = Array.from(asn1.result.certificatePolicies, element => new PolicyInformation({ schema: element }));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: Array.from(this.certificatePolicies, element => element.toSchema())
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		return {
			certificatePolicies: Array.from(this.certificatePolicies, element => element.toJSON())
		};
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class PolicyMapping
{
	//**********************************************************************************
	/**
	 * Constructor for PolicyMapping class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {string}
		 * @description issuerDomainPolicy
		 */
		this.issuerDomainPolicy = getParametersValue(parameters, "issuerDomainPolicy", PolicyMapping.defaultValues("issuerDomainPolicy"));
		/**
		 * @type {string}
		 * @description subjectDomainPolicy
		 */
		this.subjectDomainPolicy = getParametersValue(parameters, "subjectDomainPolicy", PolicyMapping.defaultValues("subjectDomainPolicy"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "issuerDomainPolicy":
				return "";
			case "subjectDomainPolicy":
				return "";
			default:
				throw new Error(`Invalid member name for PolicyMapping class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//PolicyMapping ::= SEQUENCE {
		//    issuerDomainPolicy      CertPolicyId,
		//    subjectDomainPolicy     CertPolicyId }

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [issuerDomainPolicy]
		 * @property {string} [subjectDomainPolicy]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new ObjectIdentifier({ name: (names.issuerDomainPolicy || "") }),
				new ObjectIdentifier({ name: (names.subjectDomainPolicy || "") })
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			PolicyMapping.schema({
				names: {
					issuerDomainPolicy: "issuerDomainPolicy",
					subjectDomainPolicy: "subjectDomainPolicy"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for PolicyMapping");
		//endregion

		//region Get internal properties from parsed schema
		this.issuerDomainPolicy = asn1.result.issuerDomainPolicy.valueBlock.toString();
		this.subjectDomainPolicy = asn1.result.subjectDomainPolicy.valueBlock.toString();
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: [
				new ObjectIdentifier({ value: this.issuerDomainPolicy }),
				new ObjectIdentifier({ value: this.subjectDomainPolicy })
			]
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		return {
			issuerDomainPolicy: this.issuerDomainPolicy,
			subjectDomainPolicy: this.subjectDomainPolicy
		};
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class PolicyMappings
{
	//**********************************************************************************
	/**
	 * Constructor for PolicyMappings class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Array.<PolicyMapping>}
		 * @description mappings
		 */
		this.mappings = getParametersValue(parameters, "mappings", PolicyMappings.defaultValues("mappings"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "mappings":
				return [];
			default:
				throw new Error(`Invalid member name for PolicyMappings class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		// PolicyMappings OID ::= 2.5.29.33
		//
		//PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF PolicyMapping

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [utcTimeName] Name for "utcTimeName" choice
		 * @property {string} [generalTimeName] Name for "generalTimeName" choice
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Repeated({
					name: (names.mappings || ""),
					value: PolicyMapping.schema()
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			PolicyMappings.schema({
				names: {
					mappings: "mappings"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for PolicyMappings");
		//endregion

		//region Get internal properties from parsed schema
		this.mappings = Array.from(asn1.result.mappings, element => new PolicyMapping({ schema: element }));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: Array.from(this.mappings, element => element.toSchema())
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		return {
			mappings: Array.from(this.mappings, element => element.toJSON())
		};
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class AuthorityKeyIdentifier
{
	//**********************************************************************************
	/**
	 * Constructor for AuthorityKeyIdentifier class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		if("keyIdentifier" in parameters)
			/**
			 * @type {OctetString}
			 * @description keyIdentifier
			 */
			this.keyIdentifier = getParametersValue(parameters, "keyIdentifier", AuthorityKeyIdentifier.defaultValues("keyIdentifier"));

		if("authorityCertIssuer" in parameters)
			/**
			 * @type {Array.<GeneralName>}
			 * @description authorityCertIssuer
			 */
			this.authorityCertIssuer = getParametersValue(parameters, "authorityCertIssuer", AuthorityKeyIdentifier.defaultValues("authorityCertIssuer"));

		if("authorityCertSerialNumber" in parameters)
			/**
			 * @type {Integer}
			 * @description authorityCertIssuer
			 */
			this.authorityCertSerialNumber = getParametersValue(parameters, "authorityCertSerialNumber", AuthorityKeyIdentifier.defaultValues("authorityCertSerialNumber"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "keyIdentifier":
				return new OctetString();
			case "authorityCertIssuer":
				return [];
			case "authorityCertSerialNumber":
				return new Integer();
			default:
				throw new Error(`Invalid member name for AuthorityKeyIdentifier class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		// AuthorityKeyIdentifier OID ::= 2.5.29.35
		//
		//AuthorityKeyIdentifier ::= SEQUENCE {
		//    keyIdentifier             [0] KeyIdentifier           OPTIONAL,
		//    authorityCertIssuer       [1] GeneralNames            OPTIONAL,
		//    authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
		//
		//KeyIdentifier ::= OCTET STRING

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [keyIdentifier]
		 * @property {string} [authorityCertIssuer]
		 * @property {string} [authorityCertSerialNumber]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Primitive({
					name: (names.keyIdentifier || ""),
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					}
				}),
				new Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					value: [
						new Repeated({
							name: (names.authorityCertIssuer || ""),
							value: GeneralName.schema()
						})
					]
				}),
				new Primitive({
					name: (names.authorityCertSerialNumber || ""),
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 2 // [2]
					}
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			AuthorityKeyIdentifier.schema({
				names: {
					keyIdentifier: "keyIdentifier",
					authorityCertIssuer: "authorityCertIssuer",
					authorityCertSerialNumber: "authorityCertSerialNumber"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for AuthorityKeyIdentifier");
		//endregion

		//region Get internal properties from parsed schema
		if("keyIdentifier" in asn1.result)
			this.keyIdentifier = new OctetString({ valueHex: asn1.result.keyIdentifier.valueBlock.valueHex });

		if("authorityCertIssuer" in asn1.result)
			this.authorityCertIssuer = Array.from(asn1.result.authorityCertIssuer, element => new GeneralName({ schema: element }));

		if("authorityCertSerialNumber" in asn1.result)
			this.authorityCertSerialNumber = new Integer({ valueHex: asn1.result.authorityCertSerialNumber.valueBlock.valueHex });
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Create array for output sequence
		const outputArray = [];
		
		if("keyIdentifier" in this)
		{
			const value = this.keyIdentifier;
			
			value.idBlock.tagClass = 3; // CONTEXT-SPECIFIC
			value.idBlock.tagNumber = 0; // [0]
			
			outputArray.push(value);
		}
		
		if("authorityCertIssuer" in this)
		{
			outputArray.push(new Constructed({
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 1 // [1]
				},
				value: Array.from(this.authorityCertIssuer, element => element.toSchema())
			}));
		}
		
		if("authorityCertSerialNumber" in this)
		{
			const value = this.authorityCertSerialNumber;
			
			value.idBlock.tagClass = 3; // CONTEXT-SPECIFIC
			value.idBlock.tagNumber = 2; // [2]
			
			outputArray.push(value);
		}
		//endregion
		
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: outputArray
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		const object = {};

		if("keyIdentifier" in this)
			object.keyIdentifier = this.keyIdentifier.toJSON();

		if("authorityCertIssuer" in this)
			object.authorityCertIssuer = Array.from(this.authorityCertIssuer, element => element.toJSON());

		if("authorityCertSerialNumber" in this)
			object.authorityCertSerialNumber = this.authorityCertSerialNumber.toJSON();

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class PolicyConstraints
{
	//**********************************************************************************
	/**
	 * Constructor for PolicyConstraints class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		if("requireExplicitPolicy" in parameters)
			/**
			 * @type {number}
			 * @description requireExplicitPolicy
			 */
			this.requireExplicitPolicy = getParametersValue(parameters, "requireExplicitPolicy", PolicyConstraints.defaultValues("requireExplicitPolicy"));

		if("inhibitPolicyMapping" in parameters)
			/**
			 * @type {number}
			 * @description Value of the TIME class
			 */
			this.inhibitPolicyMapping = getParametersValue(parameters, "inhibitPolicyMapping", PolicyConstraints.defaultValues("inhibitPolicyMapping"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "requireExplicitPolicy":
				return 0;
			case "inhibitPolicyMapping":
				return 0;
			default:
				throw new Error(`Invalid member name for PolicyConstraints class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		// PolicyMappings OID ::= 2.5.29.36
		//
		//PolicyConstraints ::= SEQUENCE {
		//    requireExplicitPolicy           [0] SkipCerts OPTIONAL,
		//    inhibitPolicyMapping            [1] SkipCerts OPTIONAL }
		//
		//SkipCerts ::= INTEGER (0..MAX)

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [requireExplicitPolicy]
		 * @property {string} [inhibitPolicyMapping]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Primitive({
					name: (names.requireExplicitPolicy || ""),
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					}
				}), // IMPLICIT integer value
				new Primitive({
					name: (names.inhibitPolicyMapping || ""),
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					}
				}) // IMPLICIT integer value
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			PolicyConstraints.schema({
				names: {
					requireExplicitPolicy: "requireExplicitPolicy",
					inhibitPolicyMapping: "inhibitPolicyMapping"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for PolicyConstraints");
		//endregion

		//region Get internal properties from parsed schema
		if("requireExplicitPolicy" in asn1.result)
		{
			const field1 = asn1.result.requireExplicitPolicy;

			field1.idBlock.tagClass = 1; // UNIVERSAL
			field1.idBlock.tagNumber = 2; // INTEGER

			const ber1 = field1.toBER(false);
			const int1 = fromBER(ber1);

			this.requireExplicitPolicy = int1.result.valueBlock.valueDec;
		}

		if("inhibitPolicyMapping" in asn1.result)
		{
			const field2 = asn1.result.inhibitPolicyMapping;

			field2.idBlock.tagClass = 1; // UNIVERSAL
			field2.idBlock.tagNumber = 2; // INTEGER

			const ber2 = field2.toBER(false);
			const int2 = fromBER(ber2);

			this.inhibitPolicyMapping = int2.result.valueBlock.valueDec;
		}
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Create correct values for output sequence
		const outputArray = [];
		
		if("requireExplicitPolicy" in this)
		{
			const int1 = new Integer({ value: this.requireExplicitPolicy });
			
			int1.idBlock.tagClass = 3; // CONTEXT-SPECIFIC
			int1.idBlock.tagNumber = 0; // [0]
			
			outputArray.push(int1);
		}
		
		if("inhibitPolicyMapping" in this)
		{
			const int2 = new Integer({ value: this.inhibitPolicyMapping });
			
			int2.idBlock.tagClass = 3; // CONTEXT-SPECIFIC
			int2.idBlock.tagNumber = 1; // [1]
			
			outputArray.push(int2);
		}
		//endregion
		
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: outputArray
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		const object = {};

		if("requireExplicitPolicy" in this)
			object.requireExplicitPolicy = this.requireExplicitPolicy;

		if("inhibitPolicyMapping" in this)
			object.inhibitPolicyMapping = this.inhibitPolicyMapping;

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class ExtKeyUsage
{
	//**********************************************************************************
	/**
	 * Constructor for ExtKeyUsage class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Array.<string>}
		 * @description keyPurposes
		 */
		this.keyPurposes = getParametersValue(parameters, "keyPurposes", ExtKeyUsage.defaultValues("keyPurposes"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "keyPurposes":
				return [];
			default:
				throw new Error(`Invalid member name for ExtKeyUsage class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		// ExtKeyUsage OID ::= 2.5.29.37
		//
		// ExtKeyUsage ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId

		// KeyPurposeId ::= OBJECT IDENTIFIER

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [keyPurposes]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Repeated({
					name: (names.keyPurposes || ""),
					value: new ObjectIdentifier()
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			ExtKeyUsage.schema({
				names: {
					keyPurposes: "keyPurposes"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for ExtKeyUsage");
		//endregion

		//region Get internal properties from parsed schema
		this.keyPurposes = Array.from(asn1.result.keyPurposes, element => element.valueBlock.toString());
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: Array.from(this.keyPurposes, element => new ObjectIdentifier({ value: element }))
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		return {
			keyPurposes: Array.from(this.keyPurposes)
		};
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class InfoAccess
{
	//**********************************************************************************
	/**
	 * Constructor for InfoAccess class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Array.<AccessDescription>}
		 * @description accessDescriptions
		 */
		this.accessDescriptions = getParametersValue(parameters, "accessDescriptions", InfoAccess.defaultValues("accessDescriptions"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "accessDescriptions":
				return [];
			default:
				throw new Error(`Invalid member name for InfoAccess class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		// AuthorityInfoAccess OID ::= 1.3.6.1.5.5.7.1.1
		// SubjectInfoAccess OID ::= 1.3.6.1.5.5.7.1.11
		//
		//AuthorityInfoAccessSyntax  ::=
		//SEQUENCE SIZE (1..MAX) OF AccessDescription

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [accessDescriptions]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Repeated({
					name: (names.accessDescriptions || ""),
					value: AccessDescription.schema()
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			InfoAccess.schema({
				names: {
					accessDescriptions: "accessDescriptions"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for InfoAccess");
		//endregion

		//region Get internal properties from parsed schema
		this.accessDescriptions = Array.from(asn1.result.accessDescriptions, element => new AccessDescription({ schema: element }));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: Array.from(this.accessDescriptions, element => element.toSchema())
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		return {
			accessDescriptions: Array.from(this.accessDescriptions, element => element.toJSON())
		};
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class Extension
{
	//**********************************************************************************
	/**
	 * Constructor for Extension class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {string}
		 * @description extnID
		 */
		this.extnID = getParametersValue(parameters, "extnID", Extension.defaultValues("extnID"));
		/**
		 * @type {boolean}
		 * @description critical
		 */
		this.critical = getParametersValue(parameters, "critical", Extension.defaultValues("critical"));
		/**
		 * @type {OctetString}
		 * @description extnValue
		 */
		if("extnValue" in parameters)
			this.extnValue = new OctetString({ valueHex: parameters.extnValue });
		else
			this.extnValue = Extension.defaultValues("extnValue");

		if("parsedValue" in parameters)
			/**
			 * @type {Object}
			 * @description parsedValue
			 */
			this.parsedValue = getParametersValue(parameters, "parsedValue", Extension.defaultValues("parsedValue"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "extnID":
				return "";
			case "critical":
				return false;
			case "extnValue":
				return new OctetString();
			case "parsedValue":
				return {};
			default:
				throw new Error(`Invalid member name for Extension class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//Extension  ::=  SEQUENCE  {
		//    extnID      OBJECT IDENTIFIER,
		//    critical    BOOLEAN DEFAULT FALSE,
		//    extnValue   OCTET STRING
		//}

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [extnID]
		 * @property {string} [critical]
		 * @property {string} [extnValue]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new ObjectIdentifier({ name: (names.extnID || "") }),
				new Boolean({
					name: (names.critical || ""),
					optional: true
				}),
				new OctetString({ name: (names.extnValue || "") })
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		let asn1 = compareSchema(schema,
			schema,
			Extension.schema({
				names: {
					extnID: "extnID",
					critical: "critical",
					extnValue: "extnValue"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for EXTENSION");
		//endregion

		//region Get internal properties from parsed schema
		this.extnID = asn1.result.extnID.valueBlock.toString();
		if("critical" in asn1.result)
			this.critical = asn1.result.critical.valueBlock.value;
		this.extnValue = asn1.result.extnValue;

		//region Get "parsedValue" for well-known extensions
		asn1 = fromBER(this.extnValue.valueBlock.valueHex);
		if(asn1.offset === (-1))
			return;

		switch(this.extnID)
		{
			case "2.5.29.9": // SubjectDirectoryAttributes
				this.parsedValue = new SubjectDirectoryAttributes({ schema: asn1.result });
				break;
			case "2.5.29.14": // SubjectKeyIdentifier
				this.parsedValue = asn1.result; // Should be just a simple OCTETSTRING
				break;
			case "2.5.29.15": // KeyUsage
				this.parsedValue = asn1.result; // Should be just a simple BITSTRING
				break;
			case "2.5.29.16": // PrivateKeyUsagePeriod
				this.parsedValue = new PrivateKeyUsagePeriod({ schema: asn1.result });
				break;
			case "2.5.29.17": // SubjectAltName
			case "2.5.29.18": // IssuerAltName
				this.parsedValue = new AltName({ schema: asn1.result });
				break;
			case "2.5.29.19": // BasicConstraints
				this.parsedValue = new BasicConstraints({ schema: asn1.result });
				break;
			case "2.5.29.20": // CRLNumber
			case "2.5.29.27": // BaseCRLNumber (delta CRL indicator)
				this.parsedValue = asn1.result; // Should be just a simple INTEGER
				break;
			case "2.5.29.21": // CRLReason
				this.parsedValue = asn1.result; // Should be just a simple ENUMERATED
				break;
			case "2.5.29.24": // InvalidityDate
				this.parsedValue = asn1.result; // Should be just a simple GeneralizedTime
				break;
			case "2.5.29.28": // IssuingDistributionPoint
				this.parsedValue = new IssuingDistributionPoint({ schema: asn1.result });
				break;
			case "2.5.29.29": // CertificateIssuer
				this.parsedValue = new GeneralNames({ schema: asn1.result }); // Should be just a simple
				break;
			case "2.5.29.30": // NameConstraints
				this.parsedValue = new NameConstraints({ schema: asn1.result });
				break;
			case "2.5.29.31": // CRLDistributionPoints
			case "2.5.29.46": // FreshestCRL
				this.parsedValue = new CRLDistributionPoints({ schema: asn1.result });
				break;
			case "2.5.29.32": // CertificatePolicies
				this.parsedValue = new CertificatePolicies({ schema: asn1.result });
				break;
			case "2.5.29.33": // PolicyMappings
				this.parsedValue = new PolicyMappings({ schema: asn1.result });
				break;
			case "2.5.29.35": // AuthorityKeyIdentifier
				this.parsedValue = new AuthorityKeyIdentifier({ schema: asn1.result });
				break;
			case "2.5.29.36": // PolicyConstraints
				this.parsedValue = new PolicyConstraints({ schema: asn1.result });
				break;
			case "2.5.29.37": // ExtKeyUsage
				this.parsedValue = new ExtKeyUsage({ schema: asn1.result });
				break;
			case "2.5.29.54": // InhibitAnyPolicy
				this.parsedValue = asn1.result; // Should be just a simple INTEGER
				break;
			case "1.3.6.1.5.5.7.1.1": // AuthorityInfoAccess
			case "1.3.6.1.5.5.7.1.11": // SubjectInfoAccess
				this.parsedValue = new InfoAccess({ schema: asn1.result });
				break;
			default:
		}
		//endregion
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Create array for output sequence
		const outputArray = [];

		outputArray.push(new ObjectIdentifier({ value: this.extnID }));

		if(this.critical !== Extension.defaultValues("critical"))
			outputArray.push(new Boolean({ value: this.critical }));

		outputArray.push(this.extnValue);
		//endregion

		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: outputArray
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		const object = {
			extnID: this.extnID,
			extnValue: this.extnValue.toJSON()
		};

		if(this.critical !== Extension.defaultValues("critical"))
			object.critical = this.critical;

		if("parsedValue" in this)
			object.parsedValue = this.parsedValue.toJSON();

		return object;
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5280
 */
class Extensions
{
	//**********************************************************************************
	/**
	 * Constructor for Extensions class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Array.<Extension>}
		 * @description type
		 */
		this.extensions = getParametersValue(parameters, "extensions", Extensions.defaultValues("extensions"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "extensions":
				return [];
			default:
				throw new Error(`Invalid member name for Extensions class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @param {boolean} optional Flag that current schema should be optional
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {}, optional = false)
	{
		//Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [extensions]
		 * @property {string} [extension]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			optional,
			name: (names.blockName || ""),
			value: [
				new Repeated({
					name: (names.extensions || ""),
					value: Extension.schema(names.extension || {})
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			Extensions.schema({
				names: {
					extensions: "extensions"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for EXTENSIONS");
		//endregion

		//region Get internal properties from parsed schema
		this.extensions = Array.from(asn1.result.extensions, element => new Extension({ schema: element }));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: Array.from(this.extensions, element => element.toSchema())
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		return {
			extensions: Array.from(this.extensions, element => element.toJSON())
		};
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
function tbsCertificate(parameters = {})
{
	//TBSCertificate  ::=  SEQUENCE  {
	//    version         [0]  EXPLICIT Version DEFAULT v1,
	//    serialNumber         CertificateSerialNumber,
	//    signature            AlgorithmIdentifier,
	//    issuer               Name,
	//    validity             Validity,
	//    subject              Name,
	//    subjectPublicKeyInfo SubjectPublicKeyInfo,
	//    issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
	//                         -- If present, version MUST be v2 or v3
	//    subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
	//                         -- If present, version MUST be v2 or v3
	//    extensions      [3]  EXPLICIT Extensions OPTIONAL
	//    -- If present, version MUST be v3
	//}
	
	/**
	 * @type {Object}
	 * @property {string} [blockName]
	 * @property {string} [tbsCertificateVersion]
	 * @property {string} [tbsCertificateSerialNumber]
	 * @property {string} [signature]
	 * @property {string} [issuer]
	 * @property {string} [tbsCertificateValidity]
	 * @property {string} [notBefore]
	 * @property {string} [notAfter]
	 * @property {string} [subject]
	 * @property {string} [subjectPublicKeyInfo]
	 * @property {string} [tbsCertificateIssuerUniqueID]
	 * @property {string} [tbsCertificateSubjectUniqueID]
	 * @property {string} [extensions]
	 */
	const names = getParametersValue(parameters, "names", {});
	
	return (new Sequence({
		name: (names.blockName || "tbsCertificate"),
		value: [
			new Constructed({
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 0 // [0]
				},
				value: [
					new Integer({ name: (names.tbsCertificateVersion || "tbsCertificate.version") }) // EXPLICIT integer value
				]
			}),
			new Integer({ name: (names.tbsCertificateSerialNumber || "tbsCertificate.serialNumber") }),
			AlgorithmIdentifier.schema(names.signature || {
				names: {
					blockName: "tbsCertificate.signature"
				}
			}),
			RelativeDistinguishedNames.schema(names.issuer || {
				names: {
					blockName: "tbsCertificate.issuer"
				}
			}),
			new Sequence({
				name: (names.tbsCertificateValidity || "tbsCertificate.validity"),
				value: [
					Time.schema(names.notBefore || {
						names: {
							utcTimeName: "tbsCertificate.notBefore",
							generalTimeName: "tbsCertificate.notBefore"
						}
					}),
					Time.schema(names.notAfter || {
						names: {
							utcTimeName: "tbsCertificate.notAfter",
							generalTimeName: "tbsCertificate.notAfter"
						}
					})
				]
			}),
			RelativeDistinguishedNames.schema(names.subject || {
				names: {
					blockName: "tbsCertificate.subject"
				}
			}),
			PublicKeyInfo.schema(names.subjectPublicKeyInfo || {
				names: {
					blockName: "tbsCertificate.subjectPublicKeyInfo"
				}
			}),
			new Primitive({
				name: (names.tbsCertificateIssuerUniqueID || "tbsCertificate.issuerUniqueID"),
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 1 // [1]
				}
			}), // IMPLICIT bistring value
			new Primitive({
				name: (names.tbsCertificateSubjectUniqueID || "tbsCertificate.subjectUniqueID"),
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 2 // [2]
				}
			}), // IMPLICIT bistring value
			new Constructed({
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 3 // [3]
				},
				value: [Extensions.schema(names.extensions || {
					names: {
						blockName: "tbsCertificate.extensions"
					}
				})]
			}) // EXPLICIT SEQUENCE value
		]
	}));
}
//**************************************************************************************
/**
 * Class from RFC5280
 */
class Certificate
{
	//**********************************************************************************
	/**
	 * Constructor for Certificate class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {ArrayBuffer}
		 * @description tbs
		 */
		this.tbs = getParametersValue(parameters, "tbs", Certificate.defaultValues("tbs"));
		/**
		 * @type {number}
		 * @description version
		 */
		this.version = getParametersValue(parameters, "version", Certificate.defaultValues("version"));
		/**
		 * @type {Integer}
		 * @description serialNumber
		 */
		this.serialNumber = getParametersValue(parameters, "serialNumber", Certificate.defaultValues("serialNumber"));
		/**
		 * @type {AlgorithmIdentifier}
		 * @description signature
		 */
		this.signature = getParametersValue(parameters, "signature", Certificate.defaultValues("signature"));
		/**
		 * @type {RelativeDistinguishedNames}
		 * @description issuer
		 */
		this.issuer = getParametersValue(parameters, "issuer", Certificate.defaultValues("issuer"));
		/**
		 * @type {Time}
		 * @description notBefore
		 */
		this.notBefore = getParametersValue(parameters, "notBefore", Certificate.defaultValues("notBefore"));
		/**
		 * @type {Time}
		 * @description notAfter
		 */
		this.notAfter = getParametersValue(parameters, "notAfter", Certificate.defaultValues("notAfter"));
		/**
		 * @type {RelativeDistinguishedNames}
		 * @description subject
		 */
		this.subject = getParametersValue(parameters, "subject", Certificate.defaultValues("subject"));
		/**
		 * @type {PublicKeyInfo}
		 * @description subjectPublicKeyInfo
		 */
		this.subjectPublicKeyInfo = getParametersValue(parameters, "subjectPublicKeyInfo", Certificate.defaultValues("subjectPublicKeyInfo"));
		
		if("issuerUniqueID" in parameters)
			/**
			 * @type {ArrayBuffer}
			 * @description issuerUniqueID
			 */
			this.issuerUniqueID = getParametersValue(parameters, "issuerUniqueID", Certificate.defaultValues("issuerUniqueID"));
		
		if("subjectUniqueID" in parameters)
			/**
			 * @type {ArrayBuffer}
			 * @description subjectUniqueID
			 */
			this.subjectUniqueID = getParametersValue(parameters, "subjectUniqueID", Certificate.defaultValues("subjectUniqueID"));
		
		if("extensions" in parameters)
			/**
			 * @type {Array}
			 * @description extensions
			 */
			this.extensions = getParametersValue(parameters, "extensions", Certificate.defaultValues("extensions"));
		
		/**
		 * @type {AlgorithmIdentifier}
		 * @description signatureAlgorithm
		 */
		this.signatureAlgorithm = getParametersValue(parameters, "signatureAlgorithm", Certificate.defaultValues("signatureAlgorithm"));
		/**
		 * @type {BitString}
		 * @description signatureValue
		 */
		this.signatureValue = getParametersValue(parameters, "signatureValue", Certificate.defaultValues("signatureValue"));
		//endregion
		
		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "tbs":
				return new ArrayBuffer(0);
			case "version":
				return 0;
			case "serialNumber":
				return new Integer();
			case "signature":
				return new AlgorithmIdentifier();
			case "issuer":
				return new RelativeDistinguishedNames();
			case "notBefore":
				return new Time();
			case "notAfter":
				return new Time();
			case "subject":
				return new RelativeDistinguishedNames();
			case "subjectPublicKeyInfo":
				return new PublicKeyInfo();
			case "issuerUniqueID":
				return new ArrayBuffer(0);
			case "subjectUniqueID":
				return new ArrayBuffer(0);
			case "extensions":
				return [];
			case "signatureAlgorithm":
				return new AlgorithmIdentifier();
			case "signatureValue":
				return new BitString();
			default:
				throw new Error(`Invalid member name for Certificate class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//Certificate  ::=  SEQUENCE  {
		//    tbsCertificate       TBSCertificate,
		//    signatureAlgorithm   AlgorithmIdentifier,
		//    signatureValue       BIT STRING  }
		
		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [tbsCertificate]
		 * @property {string} [signatureAlgorithm]
		 * @property {string} [signatureValue]
		 */
		const names = getParametersValue(parameters, "names", {});
		
		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				tbsCertificate(names.tbsCertificate),
				AlgorithmIdentifier.schema(names.signatureAlgorithm || {
					names: {
						blockName: "signatureAlgorithm"
					}
				}),
				new BitString({ name: (names.signatureValue || "signatureValue") })
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			Certificate.schema({
				names: {
					tbsCertificate: {
						names: {
							extensions: {
								names: {
									extensions: "tbsCertificate.extensions"
								}
							}
						}
					}
				}
			})
		);
		
		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for CERT");
		//endregion
		
		//region Get internal properties from parsed schema
		this.tbs = asn1.result.tbsCertificate.valueBeforeDecode;
		
		if("tbsCertificate.version" in asn1.result)
			this.version = asn1.result["tbsCertificate.version"].valueBlock.valueDec;
		this.serialNumber = asn1.result["tbsCertificate.serialNumber"];
		this.signature = new AlgorithmIdentifier({ schema: asn1.result["tbsCertificate.signature"] });
		this.issuer = new RelativeDistinguishedNames({ schema: asn1.result["tbsCertificate.issuer"] });
		this.notBefore = new Time({ schema: asn1.result["tbsCertificate.notBefore"] });
		this.notAfter = new Time({ schema: asn1.result["tbsCertificate.notAfter"] });
		this.subject = new RelativeDistinguishedNames({ schema: asn1.result["tbsCertificate.subject"] });
		this.subjectPublicKeyInfo = new PublicKeyInfo({ schema: asn1.result["tbsCertificate.subjectPublicKeyInfo"] });
		if("tbsCertificate.issuerUniqueID" in asn1.result)
			this.issuerUniqueID = asn1.result["tbsCertificate.issuerUniqueID"].valueBlock.valueHex;
		if("tbsCertificate.subjectUniqueID" in asn1.result)
			this.issuerUniqueID = asn1.result["tbsCertificate.subjectUniqueID"].valueBlock.valueHex;
		if("tbsCertificate.extensions" in asn1.result)
			this.extensions = Array.from(asn1.result["tbsCertificate.extensions"], element => new Extension({ schema: element }));
		
		this.signatureAlgorithm = new AlgorithmIdentifier({ schema: asn1.result.signatureAlgorithm });
		this.signatureValue = asn1.result.signatureValue;
		//endregion
	}
	//**********************************************************************************
	/**
	 * Create ASN.1 schema for existing values of TBS part for the certificate
	 */
	encodeTBS()
	{
		//region Create array for output sequence
		const outputArray = [];
		
		if(("version" in this) && (this.version !== Certificate.defaultValues("version")))
		{
			outputArray.push(new Constructed({
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 0 // [0]
				},
				value: [
					new Integer({ value: this.version }) // EXPLICIT integer value
				]
			}));
		}
		
		outputArray.push(this.serialNumber);
		outputArray.push(this.signature.toSchema());
		outputArray.push(this.issuer.toSchema());
		
		outputArray.push(new Sequence({
			value: [
				this.notBefore.toSchema(),
				this.notAfter.toSchema()
			]
		}));
		
		outputArray.push(this.subject.toSchema());
		outputArray.push(this.subjectPublicKeyInfo.toSchema());
		
		if("issuerUniqueID" in this)
		{
			outputArray.push(new Primitive({
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 1 // [1]
				},
				valueHex: this.issuerUniqueID
			}));
		}
		if("subjectUniqueID" in this)
		{
			outputArray.push(new Primitive({
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 2 // [2]
				},
				valueHex: this.subjectUniqueID
			}));
		}
		
		if("subjectUniqueID" in this)
		{
			outputArray.push(new Primitive({
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 3 // [3]
				},
				value: [this.extensions.toSchema()]
			}));
		}
		
		if("extensions" in this)
		{
			outputArray.push(new Constructed({
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 3 // [3]
				},
				value: [new Sequence({
					value: Array.from(this.extensions, element => element.toSchema())
				})]
			}));
		}
		//endregion
		
		//region Create and return output sequence
		return (new Sequence({
			value: outputArray
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema(encodeFlag = false)
	{
		let tbsSchema = {};
		
		//region Decode stored TBS value
		if(encodeFlag === false)
		{
			if(this.tbs.length === 0) // No stored certificate TBS part
				return Certificate.schema().value[0];
			
			tbsSchema = fromBER(this.tbs).result;
		}
		//endregion
		//region Create TBS schema via assembling from TBS parts
		else
			tbsSchema = this.encodeTBS();
		//endregion
		
		//region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: [
				tbsSchema,
				this.signatureAlgorithm.toSchema(),
				this.signatureValue
			]
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		const object = {
			tbs: bufferToHexCodes(this.tbs, 0, this.tbs.byteLength),
			serialNumber: this.serialNumber.toJSON(),
			signature: this.signature.toJSON(),
			issuer: this.issuer.toJSON(),
			notBefore: this.notBefore.toJSON(),
			notAfter: this.notAfter.toJSON(),
			subject: this.subject.toJSON(),
			subjectPublicKeyInfo: this.subjectPublicKeyInfo.toJSON(),
			signatureAlgorithm: this.signatureAlgorithm.toJSON(),
			signatureValue: this.signatureValue.toJSON()
		};
		
		if(("version" in this) && (this.version !== Certificate.defaultValues("version")))
			object.version = this.version;
		
		if("issuerUniqueID" in this)
			object.issuerUniqueID = bufferToHexCodes(this.issuerUniqueID, 0, this.issuerUniqueID.byteLength);
		
		if("subjectUniqueID" in this)
			object.subjectUniqueID = bufferToHexCodes(this.subjectUniqueID, 0, this.subjectUniqueID.byteLength);
		
		if("extensions" in this)
			object.extensions = Array.from(this.extensions, element => element.toJSON());
		
		return object;
	}
	//**********************************************************************************
	/**
	 * Importing public key for current certificate
	 */
	getPublicKey(parameters = null)
	{
		return getEngine().subtle.getPublicKey(this.subjectPublicKeyInfo, this.signatureAlgorithm, parameters);
	}
	//**********************************************************************************
	/**
	 * Get SHA-1 hash value for subject public key
	 */
	getKeyHash()
	{
		//region Get a "crypto" extension
		const crypto = getCrypto();
		if(typeof crypto === "undefined")
			return Promise.reject("Unable to create WebCrypto object");
		//endregion
		
		return crypto.digest({ name: "sha-1" }, new Uint8Array(this.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex));
	}
	//**********************************************************************************
	/**
	 * Make a signature for current value from TBS section
	 * @param {Object} privateKey Private key for "subjectPublicKeyInfo" structure
	 * @param {string} [hashAlgorithm="SHA-1"] Hashing algorithm
	 */
	sign(privateKey, hashAlgorithm = "SHA-1")
	{
		//region Initial checking
		//region Check private key
		if(typeof privateKey === "undefined")
			return Promise.reject("Need to provide a private key for signing");
		//endregion
		//endregion
		
		//region Initial variables
		let sequence = Promise.resolve();
		let parameters;
		
		const engine = getEngine();
		//endregion
		
		//region Get a "default parameters" for current algorithm and set correct signature algorithm
		sequence = sequence.then(() => engine.subtle.getSignatureParameters(privateKey, hashAlgorithm));
		
		sequence = sequence.then(result =>
		{
			parameters = result.parameters;
			this.signature = result.signatureAlgorithm;
			this.signatureAlgorithm = result.signatureAlgorithm;
		});
		//endregion
		
		//region Create TBS data for signing
		sequence = sequence.then(() =>
		{
			this.tbs = this.encodeTBS().toBER(false);
		});
		//endregion
		
		//region Signing TBS data on provided private key
		sequence = sequence.then(() => engine.subtle.signWithPrivateKey(this.tbs, privateKey, parameters));
		
		sequence = sequence.then(result =>
		{
			this.signatureValue = new BitString({ valueHex: result });
		});
		//endregion
		
		return sequence;
	}
	//**********************************************************************************
	verify(issuerCertificate = null)
	{
		//region Global variables
		let subjectPublicKeyInfo = {};
		//endregion
		
		//region Set correct "subjectPublicKeyInfo" value
		if(issuerCertificate !== null)
			subjectPublicKeyInfo = issuerCertificate.subjectPublicKeyInfo;
		else
		{
			if(this.issuer.isEqual(this.subject)) // Self-signed certificate
				subjectPublicKeyInfo = this.subjectPublicKeyInfo;
		}
		
		if((subjectPublicKeyInfo instanceof PublicKeyInfo) === false)
			return Promise.reject("Please provide issuer certificate as a parameter");
		//endregion
		
		return getEngine().subtle.verifyWithPublicKey(this.tbs, this.signatureValue, subjectPublicKeyInfo, this.signatureAlgorithm);
	}
	//**********************************************************************************
}
//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5755
 */

//**************************************************************************************
/**
 * Class from RFC5755
 */

//**************************************************************************************
/**
 * Class from RFC5755
 */


//**************************************************************************************

//**************************************************************************************
/**
 * Class from RFC5755
 */

//**************************************************************************************
/**
 * Class from RFC5755
 */

//**************************************************************************************
/**
 * Class from RFC5755
 */

//**************************************************************************************
/**
 * Class from RFC5755
 */


//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

//**************************************************************************************

/**
 * Certificate Transparency Utilities
 * Common helper functions
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

/**
 * Convert an uint64 to an ArrayBuffer with big-endian encoding.
 * @param {number} num - The number to convert.
 * @return {ArrayBuffer} An ArrayBuffer containing the number.
 */
function uint64ToArrayBuffer(num) {
  const ret = new ArrayBuffer(8);
  const retView = new Uint8Array(ret);

  for(let i = 0; i < 8; i++)
    retView[i] = ~~(num / (2 ** (8 * (7 - i)))) & 0xff;

  return ret;
}

/**
 * Convert the contents of an ArrayBuffer to an uint64 with big-endian encoding.
 * The ArrayBuffer must have at least 8 bytes, the rest are ignored.
 * @param {ArrayBuffer} buf - The ArrayBuffer.
 * @return {number} The unsigned 64 bit integer.
 */
function arrayBufferToUint64(buf) {
  let ret = 0;
  const bufView = new Uint8Array(buf);

  for(let i = 0; i < 8; i++)
    ret += bufView[i] * (2 ** (8 * (7 - i)));

  return ret;
}

/**
 * Create a query string from an object with parameters.
 * @param {Object} params - The object with the parameters.
 * @return {string} The resulting string.
 */
function paramsToQueryString(params) {
  return Object.keys(params).map(k =>
    encodeURIComponent(k) + '=' + encodeURIComponent(params[k])).join('&');
}

/**
 * Certificate Transparency Utilities
 * Various enums
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

/**
 * Version
 */
const Version = Object.freeze({
  v1: 0
});

/**
 * Entry type
 */
const LogEntryType = Object.freeze({
  x509_entry: 0,
  precert_entry: 1
});

/**
 * Leaf type at Merkle Tree
 */
const MerkleLeafType = Object.freeze({
  timestamped_entry: 0
});

/**
 * Signature type
 */
const SignatureType = Object.freeze({
  certificate_timestamp: 0,
  tree_hash: 1
});

/**
 * Certificate Transparency Utilities
 * TimestampedEntry class
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

/**
 * TimestampedEntry class
 */
class TimestampedEntry {
  /**
   * Construct a TimestampedEntry.
   * @param {number} timestamp - The timestamp of the entry.
   * @param {number} type - The type of the entry.
   * @param {ArrayBuffer} cert - The certificate or precertificate of the entry.
   * @param {ArrayBuffer} extensions - The extensions of the entry.
   */
  constructor(timestamp, type, cert, extensions) {
    /**
     * @type number
     * @description The timestamp of the entry.
     */
    this.timestamp = timestamp;
    /**
     * @type number
     * @description The type of the entry.
     */
    this.type = type;
    /**
     * @type ArrayBuffer
     * @description The certificate or precertificate of the entry.
     */
    this.cert = cert;
    /**
     * @type ArrayBuffer
     * @description The extensions of the entry.
     */
    this.extensions = extensions;
  }

  /**
   * Encode the entry and get the binary representation.
   * @return {ArrayBuffer} An ArrayBuffer containing the binary representation
   * of the entry.
   */
  toBinary() {
    let certView;
    let timestampedEntryLen;

    const extensionsView = new Uint8Array(this.extensions);

    certView = new Uint8Array(this.cert);
    if(this.type === LogEntryType.x509_entry)
      timestampedEntryLen = 15 + certView.length + extensionsView.length;
    else
      timestampedEntryLen = 12 + certView.length + extensionsView.length;

    const timestampedEntry = new ArrayBuffer(timestampedEntryLen);
    const timestampedEntryView = new Uint8Array(timestampedEntry);

    timestampedEntryView.set(new Uint8Array(uint64ToArrayBuffer(
      this.timestamp)));

    timestampedEntryView[8] = (this.type >> 8) & 0xff;
    timestampedEntryView[9] = this.type & 0xff;

    let offset = 10;

    if(this.type === LogEntryType.x509_entry) {
      timestampedEntryView[10] = (certView.length >> 16) & 0xff;
      timestampedEntryView[11] = (certView.length >> 8) & 0xff;
      timestampedEntryView[12] = certView.length & 0xff;
      offset += 3;
    }
    timestampedEntryView.set(certView, offset);

    timestampedEntryView[offset + certView.length] =
      (extensionsView.length >> 8) & 0xff;
    timestampedEntryView[offset + certView.length + 1] =
      extensionsView.length & 0xff;

    if(extensionsView.length > 0)
      timestampedEntryView.set(extensionsView, offset + 2 + certView.length);

    return timestampedEntry;
  }

  /**
   * Parse a binary TimestampedEntry and return a new object.
   * @param {ArrayBuffer} timestampedEntryBin - The binary TimestampedEntry.
   * @return {TimestampedEntry} The TimestampedEntry object.
   */
  static fromBinary(timestampedEntryBin) {
    const timestampedEntryBinView = new Uint8Array(timestampedEntryBin);

    const timestamp = arrayBufferToUint64(
      timestampedEntryBinView.slice(0, 8).buffer);

    const type = (timestampedEntryBinView[8] << 8) + timestampedEntryBinView[9];

    let cert, extensions;

    if(type === LogEntryType.x509_entry) {
      const certLen = (timestampedEntryBinView[10] << 16) +
        (timestampedEntryBinView[11] << 8) + timestampedEntryBinView[12];
      cert = timestampedEntryBinView.slice(13, 13 + certLen).buffer;
      extensions = timestampedEntryBinView.slice(13 + 2 + certLen).buffer;
    } else {
      let preCertLen = 32;
      preCertLen += (timestampedEntryBinView[42] << 16) +
        (timestampedEntryBinView[43] << 8) + timestampedEntryBinView[44];
      cert = timestampedEntryBinView.slice(10, 10 + 3 + preCertLen).buffer;
      extensions = timestampedEntryBinView.slice(10 + 3 + preCertLen + 2).buffer;
    }

    return new TimestampedEntry(timestamp, type, cert, extensions);
  }
}

/**
 * Certificate Transparency Utilities
 * MerkleTreeLeaf class
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

/**
 * MerkleTreeLeaf class
 */
class MerkleTreeLeaf {
  /**
   * Construct a TimestampedEntry.
   * @param {number} version - The version.
   * @param {number} type - The type of the leaf.
   * @param {TimestampedEntry} timestampedEntry - The TimestampedEntry.
   */
  constructor(version, type, timestampedEntry) {
    /**
     * @type number
     * @description The version.
     */
    this.version = version;
    /**
     * @type number
     * @description The type of the leaf.
     */
    this.type = type;
    /**
     * @type TimestampedEntry
     * @description The TimestampedEntry.
     */
    this.timestampedEntry = timestampedEntry;
  }

  /**
   * Encode the leaf and get the binary representation.
   * @return {ArrayBuffer} An ArrayBuffer containing the binary representation
   * of the leaf.
   */
  toBinary() {
    const timestampedEntryBuf = this.timestampedEntry.toBinary();
    const timestampedEntryView = new Uint8Array(timestampedEntryBuf);
    const merkleTreeLeaf = new ArrayBuffer(2 + timestampedEntryView.length);
    const merkleTreeLeafView = new Uint8Array(merkleTreeLeaf);

    merkleTreeLeafView[0] = this.version;

    merkleTreeLeafView[1] = this.type;

    merkleTreeLeafView.set(timestampedEntryView, 2);

    return merkleTreeLeaf;
  }

  /**
   * Parse a binary MerkleTreeLeaf and return a new object.
   * @param {ArrayBuffer} merkleTreeLeafBin - The binary MerkleTreeLeaf.
   * @return {MerkleTreeLeaf} The MerkleTreeLeaf object.
   */
  static fromBinary(merkleTreeLeafBin) {
    const merkleTreeLeafBinView = new Uint8Array(merkleTreeLeafBin);

    const version = merkleTreeLeafBinView[0];

    const type = merkleTreeLeafBinView[1];

    const timestampedEntryBuf = merkleTreeLeafBinView.slice(2).buffer;

    const timestampedEntry = TimestampedEntry.fromBinary(timestampedEntryBuf);

    return new MerkleTreeLeaf(version, type, timestampedEntry);
  }

  /**
   * Get the hash of the leaf.
   * Per section 2.1 of RFC6962 to generate the hash of a leaf, a \x00 needs to
   * be prepended.
   * @return {Promise.<ArrayBuffer>} A Promise that is resolved with the hash of
   * the leaf.
   */
  getHash() {
    const webcrypto = getEngine();
    const merkleTreeLeafView = new Uint8Array(this.toBinary());
    const toHash = new ArrayBuffer(merkleTreeLeafView.length + 1);
    const toHashView = new Uint8Array(toHash);

    toHashView[0] = 0;
    toHashView.set(merkleTreeLeafView, 1);

    return webcrypto.subtle.digest({ name: 'SHA-256' }, toHash);
  }

  /**
   * Verify the inclusion of a leaf by hash.
   * This is a static function, so it can be used directly if there are no
   * details for the leaf other than its hash.
   * @param {SignedTreeHead} sth - The SignedTreeHead against which the check
   * will be made.
   * @param {number} index - The index of the leaf in the tree.
   * @param {Array.<ArrayBuffer>} auditPath - The audit path.
   * @param {ArrayBuffer} hash - The hash of the leaf.
   * @return {Promise.<Boolean>} A promise that is resolved with the result
   * of the inclusion verification.
   */
  static verifyInclusionByHash(sth, index, auditPath, hash) {
    if(index > sth.treeSize)
      return Promise.reject(new Error('Index is greater than tree size'));

    /* Calculate the expected size of the audit path */
    let length = 0;
    let lastNode = sth.treeSize - 1;
    let tmpIndex = index;
    while(lastNode > 0) {
      if(((tmpIndex % 2) > 0) || (tmpIndex < lastNode))
        length++;
      tmpIndex = Math.floor(tmpIndex / 2);
      lastNode = Math.floor(lastNode / 2);
    }

    if(auditPath.length !== length)
      return Promise.reject(new Error('Audit path size wrong'));

    /* Start verification */

    let sequence = Promise.resolve(hash);
    lastNode = sth.treeSize - 1;

    const auditPathArray = auditPath.slice();

    /* The whole sequence is resolved by the latest calculated hash */
    while(lastNode > 0) {
      if((index % 2) > 0) {
        sequence = sequence.then(h => {
          const hashView = new Uint8Array(h);
          const nodeView = new Uint8Array(auditPathArray.shift());

          const data = new ArrayBuffer(hashView.length + nodeView.length + 1);
          const dataView = new Uint8Array(data);

          const webcrypto = getEngine();

          dataView[0] = 0x01;
          dataView.set(nodeView, 1);
          dataView.set(hashView, 1 + nodeView.length);

          return webcrypto.subtle.digest({ name: 'SHA-256' }, data);
        });
      } else {
        sequence = sequence.then(h => {
          const hashView = new Uint8Array(h);
          const nodeView = new Uint8Array(auditPathArray.shift());

          const data = new ArrayBuffer(hashView.length + nodeView.length + 1);
          const dataView = new Uint8Array(data);

          const webcrypto = getEngine();

          dataView[0] = 0x01;
          dataView.set(hashView, 1);
          dataView.set(nodeView, 1 + hashView.length);

          return webcrypto.subtle.digest({ name: 'SHA-256' }, data);
        });
      }

      index = Math.floor(index / 2);
      lastNode = Math.floor(lastNode / 2);
    }

    /* Finally compare the calculated root hash against the actual one */
    sequence = sequence.then(h => {
      const hashView = new Uint8Array(h);
      const rootView = new Uint8Array(sth.rootHash);

      if(hashView.length !== rootView.length)
        return false;

      for(let i = 0; i < hashView.length; i++)
        if(hashView[i] !== rootView[i])
          return false;

      return true;
    });

    return sequence;
  }

  /**
   * Verify the inclusion of this leaf in a log.
   * @param {SignedTreeHead} sth - The SignedTreeHead against which the check
   * will be made.
   * @param {number} index - The index of the leaf in the tree.
   * @param {Array.<ArrayBuffer>} auditPath - The audit path.
   * @return {Promise.<Boolean>} A promise that is resolved with the result
   * of the inclusion verification.
   */
  verifyInclusion(sth, index, auditPath) {
    return this.getHash().then(h =>
      MerkleTreeLeaf.verifyInclusionByHash(sth, index, auditPath, h)
    );
  }
}

/**
 * Certificate Transparency Utilities
 * SCT class
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

/**
 * SCT class
 */
class SignedCertificateTimestamp {
  /**
   * Construct an SCT object.
   * @param {number} version - The version of the SCT, currently only 1 is
   * defined and supported.
   * @param {ArrayBuffer} logId - The id of the log.
   * @param {number} timestamp - The timestamp of the SCT.
   * @param {ArrayBuffer} extensions - The extensions.
   * @param {ArrayBuffer} signature - The signature.
   * @param {number} type - The type of the entry, either
   * LogEntryType.x509_entry or LogEntryType.precert_entry.
   * @param {ArrayBuffer} cert - The certificate or precertificate
   * for this SCT.
   */
  constructor(version, logId, timestamp, extensions, signature,
    type = LogEntryType.x509_entry, cert = null) {
    /**
     * @type {number}
     * @description The version of the SCT.
     */
    this.version = version;
    /**
     * @type {ArrayBuffer}
     * @description The id of the log.
     */
    this.logId = logId;
    /**
     * @type {number}
     * @description The timestamp of the SCT.
     */
    this.timestamp = timestamp;
    /**
     * @type {ArrayBuffer}
     * @description The extensions.
     */
    this.extensions = extensions;
    /**
     * @type {ArrayBuffer}
     * @description The signature.
     */
    this.signature = signature;
    /**
     * @type {number}
     * @description The type of the entry.
     */
    this.type = type;
    /**
     * @type {ArrayBuffer}
     * @description The certificate or precertificate for this SCT.
     */
    this.cert = cert;
  }

  /**
   * Encode the SCT and get the binary representation.
   * @return {ArrayBuffer} An ArrayBuffer containing the binary representation
   * of the SCT.
   */
  toBinary() {
    const logIdView = new Uint8Array(this.logId);
    const extensionsView = new Uint8Array(this.extensions);
    const signatureView = new Uint8Array(this.signature);

    /*
     * Total size is calculated from the following:
     * 1 byte: version
     * 32 bytes: log id
     * 8 bytes: timestamp
     * 2 bytes: length of extensions
     * extensionsView.length bytes: the extensions
     * signatureView.length bytes: the signature
     */
    const sctLen = 1 + 32 + 8 + 2 + extensionsView.length +
      signatureView.length;
    const sct = new ArrayBuffer(sctLen);
    const sctView = new Uint8Array(sct);

    sctView[0] = this.version;

    sctView.set(logIdView, 1);

    sctView.set(new Uint8Array(uint64ToArrayBuffer(this.timestamp)), 33);

    sctView[41] = (extensionsView.length >> 8) & 0xff;
    sctView[42] = extensionsView.length & 0xff;

    sctView.set(extensionsView, 43);

    sctView.set(signatureView, 43 + extensionsView.length);

    return sct;
  }

  /**
   * Parse a binary SCT and return a new SCT object.
   * @param {ArrayBuffer} sctBin - The binary SCT.
   * @param {number} type - The type of the entry.
   * @param {ArrayBuffer} cert - The certificate or precertificate
   * for this SCT.
   * @return {SCT} An SCT object containing all information from the binary SCT.
   */
  static fromBinary(sctBin, type = LogEntryType.x509_entry, cert = null) {
    const sctBinView = new Uint8Array(sctBin);

    const version = sctBinView[0];

    const logId = sctBinView.slice(1, 33).buffer;

    const timestamp = arrayBufferToUint64(sctBinView.slice(33, 41).buffer);

    const extLen = (sctBinView[41] << 8) + sctBinView[42];
    const extensions = sctBinView.slice(43, 43 + extLen).buffer;

    const signature = sctBinView.slice(43 + extLen).buffer;

    return new SignedCertificateTimestamp(version, logId, timestamp, extensions,
      signature, type, cert);
  }

  /**
   * Verify the signature of an SCT.
   * @param {(ArrayBuffer|CTLog)} log - The public key of the log as an
   * ArrayBuffer, or a CTLog object.
   * @return {Promise.<Boolean>} A promise that is resolved with the result
   * of the verification.
   */
  verify(log) {
    let pubKey;
    if(log instanceof CTLog) {
      pubKey = log.pubKey;
    } else if(log instanceof ArrayBuffer) {
      pubKey = log;
    } else {
      return Promise.reject(new Error('Unknown key type'));
    }

    let sequence = Promise.resolve();
    const signatureView = new Uint8Array(this.signature);

    const certView = new Uint8Array(this.cert);
    const extensionsView = new Uint8Array(this.extensions);

    const dataStructLen = 17 + certView.length + extensionsView.length;
    const dataStruct = new ArrayBuffer(dataStructLen);
    const dataStructView = new Uint8Array(dataStruct);

    /*
     * Prepare the struct with the data that was signed.
     */
    dataStructView[0] = this.version;

    dataStructView[1] = SignatureType.certificate_timestamp;

    dataStructView.set(new Uint8Array(uint64ToArrayBuffer(this.timestamp)), 2);

    dataStructView[10] = (this.type >> 8) & 0xff;
    dataStructView[11] = this.type & 0xff;

    dataStructView[12] = (certView.length >> 16) & 0xff;
    dataStructView[13] = (certView.length >> 8) & 0xff;
    dataStructView[14] = certView.length & 0xff;

    dataStructView.set(certView, 15);

    dataStructView[16 + certView.length] =
      (extensionsView.length >> 8) & 0xff;
    dataStructView[16 + certView.length + 1] =
      extensionsView.length & 0xff;

    if(extensionsView.length > 0)
      dataStructView.set(extensionsView, 18 + certView.length);

    /*
     * Per RFC6962 all signatures are either ECDSA with the NIST P-256 curve
     * or RSA (RSASSA-PKCS1-V1_5) with SHA-256.
     */
    const isECDSA = signatureView[1] === 3;

    const pubKeyView = new Uint8Array(pubKey);

    const webcrypto = getEngine();

    sequence = sequence.then(() => {
      let opts;

      if(isECDSA) {
        opts = {
          name: 'ECDSA',
          namedCurve: 'P-256'
        };
      } else {
        opts = {
          name: 'RSASSA-PKCS1-v1_5',
          hash: {
            name: 'SHA-256'
          }
        };
      }

      return webcrypto.subtle.importKey('spki', pubKeyView, opts, false,
        ['verify']);
    });

    sequence = sequence.then(publicKey => {
      let opts;

      if(isECDSA) {
        opts = {
          name: 'ECDSA',
          hash: {
            name: 'SHA-256'
          }
        };
      } else {
        opts = {
          name: 'RSASSA-PKCS1-v1_5'
        };
      }

      if(isECDSA) {
        /*
         * Convert from a CMS signature to a webcrypto compatible one.
         */
        const asn1 = fromBER(this.signature.slice(4));
        const ecdsaSig = createECDSASignatureFromCMS(asn1.result);
        return webcrypto.subtle.verify(opts, publicKey, ecdsaSig, dataStruct);
      } else {
        return webcrypto.subtle.verify(opts, publicKey, this.signature.slice(4),
          dataStruct);
      }
    });

    return sequence;
  }

  /**
   * Get the signature algorithm.
   * @return {number} The signature algorithm of the digitally signed struct,
   * as defined in RFC5246, i.e. 1 for RSA and 3 for ECDSA.
   */
  getSignatureAlgorithm() {
    const signatureView = new Uint8Array(this.signature);

    return signatureView[1];
  }

  /**
   * Get the internal signature of the SCT.
   * @return {ArrayBuffer} The internal signature of the digitally signed
   * struct.
   */
  getInternalSignature() {
    return this.signature.slice(4);
  }

  /**
   * Set the signature of the SCT.
   * @param {number} algorithm - The signature algorithm as defined in RFC5246.
   * @param {ArrayBuffer} signature - The internal signature.
   */
  setSignature(algorithm, signature) {
    const newSigView = new Uint8Array(signature);
    this.signature = new ArrayBuffer(4 + newSigView.length);
    const sigView = new Uint8Array(this.signature);

    /* Hash algorithm is always SHA256 */
    sigView[0] = 4;
    sigView[1] = algorithm;
    sigView[2] = (newSigView.length >> 8) & 0xff;
    sigView[3] = newSigView.length & 0xff;

    for(let i = 0; i < newSigView.length; i++)
      sigView[4 + i] = newSigView[i];
  }
}

/**
 * Certificate Transparency Utilities
 * SignedTreeHead class
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

/**
 * SignedTreeHead class
 */
class SignedTreeHead {
  /**
   * Construct a SignedTreeHead.
   * @param {number} treeSize - The size of the tree.
   * @param {number} timestamp - The timestamp.
   * @param {ArrayBuffer} rootHash - The Merkle Tree Hash.
   * @param {ArrayBuffer} signature - The signature.
   * @param {number} version - The version.
   */
  constructor(treeSize, timestamp, rootHash, signature, version) {
    /**
     * @type {number}
     * @description The size of the tree.
     */
    this.treeSize = treeSize;
    /**
     * @type {number}
     * @description The timestamp.
     */
    this.timestamp = timestamp;
    /**
     * @type {ArrayBuffer}
     * @description The Merkle Tree Hash.
     */
    this.rootHash = rootHash;
    /**
     * @type {ArrayBuffer}
     * @description The signature.
     */
    this.signature = signature;
    /**
     * @type {number}
     * @description The version.
     */
    this.version = version;
  }

  /**
   * Verify the signature of an SignedTreeHead.
   * @param {(ArrayBuffer|CTLog)} log - The public key of the log as an
   * ArrayBuffer, or a CTLog object.
   * @return {Promise.<Boolean>} A promise that is resolved with the result
   * of the verification.
   */
  verify(log) {
    let pubKey;
    if(log instanceof CTLog) {
      pubKey = log.pubKey;
    } else if(log instanceof ArrayBuffer) {
      pubKey = log;
    } else {
      return Promise.reject(new Error('Unknown key type'));
    }

    let sequence = Promise.resolve();
    const signatureView = new Uint8Array(this.signature);

    const dataStruct = new ArrayBuffer(50);
    const dataStructView = new Uint8Array(dataStruct);

    /*
     * Prepare the struct with the data that was signed.
     */
    dataStructView[0] = this.version;

    dataStructView[1] = SignatureType.tree_hash;

    dataStructView.set(new Uint8Array(uint64ToArrayBuffer(this.timestamp)), 2);

    dataStructView.set(new Uint8Array(uint64ToArrayBuffer(this.treeSize)), 10);

    dataStructView.set(new Uint8Array(this.rootHash), 18);

    /*
     * Per RFC6962 all signatures are either ECDSA with the NIST P-256 curve
     * or RSA (RSASSA-PKCS1-V1_5) with SHA-256.
     */
    const isECDSA = signatureView[1] === 3;

    const pubKeyView = new Uint8Array(pubKey);

    const webcrypto = getEngine();

    sequence = sequence.then(() => {
      let opts;

      if(isECDSA) {
        opts = {
          name: 'ECDSA',
          namedCurve: 'P-256'
        };
      } else {
        opts = {
          name: 'RSASSA-PKCS1-v1_5',
          hash: {
            name: 'SHA-256'
          }
        };
      }

      return webcrypto.subtle.importKey('spki', pubKeyView, opts, false,
        ['verify']);
    });

    sequence = sequence.then(publicKey => {
      let opts;

      if(isECDSA) {
        opts = {
          name: 'ECDSA',
          hash: {
            name: 'SHA-256'
          }
        };
      } else {
        opts = {
          name: 'RSASSA-PKCS1-v1_5'
        };
      }

      if(isECDSA) {
        /*
         * Convert from a CMS signature to a webcrypto compatible one.
         */
        const asn1 = fromBER(this.signature.slice(4));
        const ecdsaSig = createECDSASignatureFromCMS(asn1.result);
        return webcrypto.subtle.verify(opts, publicKey, ecdsaSig, dataStruct);
      } else {
        return webcrypto.subtle.verify(opts, publicKey, this.signature.slice(4),
          dataStruct);
      }
    });

    return sequence;
  }

  /**
   * Verify consistency between two Signed Tree Heads.
   * @param {SignedTreeHead} second - The second SignedTreeHead.
   * @param {Array.<ArrayBuffer>} proofs - The consistency proofs.
   * @return {Promise.<Boolean>} A promise that is resolved with the
   * result of the consistency verification.
   */
  verifyConsistency(second, proofs) {
    /**
     * Both functions return an array whose first item is the old hash
     * and the second item is the new hash. This helps in creating
     * the chain during the verification.
     */
    const hashRightChild = async (oldHash, newHash, node) => {
      const oldHashView = new Uint8Array(oldHash);
      const newHashView = new Uint8Array(newHash);
      const nodeView = new Uint8Array(node);

      const data = new ArrayBuffer(oldHashView.length + nodeView.length + 1);
      const dataView = new Uint8Array(data);

      const webcrypto = getEngine();

      dataView[0] = 0x01;
      dataView.set(nodeView, 1);
      dataView.set(oldHashView, 1 + nodeView.length);

      oldHash = await webcrypto.subtle.digest({ name: 'SHA-256' }, data);

      dataView.set(newHashView, 1 + nodeView.length);

      newHash = await webcrypto.subtle.digest({ name: 'SHA-256' }, data);

      return [ oldHash, newHash ];
    };
    const hashLeftChild = async (oldHash, newHash, node) => {
      const newHashView = new Uint8Array(newHash);
      const nodeView = new Uint8Array(node);

      const data = new ArrayBuffer(newHashView.length + nodeView.length + 1);
      const dataView = new Uint8Array(data);

      const webcrypto = getEngine();

      dataView[0] = 0x01;
      dataView.set(newHashView, 1);
      dataView.set(nodeView, 1 + newHashView.length);

      newHash = await webcrypto.subtle.digest({ name: 'SHA-256' }, data);

      return [ oldHash, newHash ];
    };

    let oldSTH, newSTH;
    if(this.timestamp <= second.timestamp) {
      oldSTH = this;
      newSTH = second;
    } else {
      oldSTH = second;
      newSTH = this;
    }

    if(oldSTH.treeSize > newSTH.treeSize)
      return Promise.reject(new Error('Older tree is bigger than first'));

    /**
     * If the old tree is empty or has the same number of elements with the
     * new we assume it's valid.
     */
    if(oldSTH.treeSize === 0)
      return Promise.resolve(true);

    if(oldSTH.treeSize === newSTH.treeSize) {
      const oldRootHashView = new Uint8Array(oldSTH.rootHash);
      const newRootHashView = new Uint8Array(newSTH.rootHash);

      if(oldRootHashView.length !== newRootHashView.length)
        return Promise.resolve(false);

      for(let i = 0; i < oldRootHashView; i++)
        if(oldRootHashView[i] !== newRootHashView[i])
          return Promise.resolve(false);

      return Promise.resolve(true);
    }

    /* Calculate the expected size of the proof */
    let length = 0;
    let b = 0;
    let m = oldSTH.treeSize;
    let n = newSTH.treeSize;

    while(m !== n) {
      length++;

      const k = 2 ** Math.floor(Math.log2(n - 1));

      if(m <= k) {
        n = k;
      } else {
        m -= k;
        n -= k;
        b = 1;
      }
    }

    length += b;

    if(proofs.length !== length)
      return Promise.reject(new Error('Proof size wrong'));

    /* Start verification */

    let node = oldSTH.treeSize - 1;
    let lastNode = newSTH.treeSize - 1;

    while((node % 2) > 0) {
      node = Math.floor(node / 2);
      lastNode = Math.floor(lastNode / 2);
    }

    const proofArray = proofs.slice();

    let sequence;
    /**
     * Sequence is resolved with old hash and new hash in order to be ready
     * for input to the chain of calls below.
     */
    if(node > 0) {
      const h = proofArray.shift();
      sequence = Promise.resolve([h, h]);
    } else {
      sequence = Promise.resolve([oldSTH.rootHash, oldSTH.rootHash]);
    }

    /**
     * The following chain of calls to hashRightChild and hashLeftChild works
     * because both callbacks for success expect an array with the old hash
     * and the new one, and return such an array.
     */
    while(node > 0) {
      if((node % 2) > 0) {
        sequence = sequence.then((args) => {
          const oldHash = args[0];
          const newHash = args[1];
          return hashRightChild(oldHash, newHash, proofArray.shift())
        });
      } else if(node < lastNode) {
        sequence = sequence.then((args) => {
          const oldHash = args[0];
          const newHash = args[1];
          return hashLeftChild(oldHash, newHash, proofArray.shift())
        });
      }

      node = Math.floor(node / 2);
      lastNode = Math.floor(lastNode / 2);
    }

    while(lastNode > 0) {
      sequence = sequence.then((args) => {
        const oldHash = args[0];
        const newHash = args[1];
        return hashLeftChild(oldHash, newHash, proofArray.shift())
      });
      lastNode = Math.floor(lastNode / 2);
    }

    /* Finally compare calculated root hashes against the actual ones */
    sequence = sequence.then((args) => {
      const oldHash = args[0];
      const newHash = args[1];
      const oldHashView = new Uint8Array(oldHash);
      const newHashView = new Uint8Array(newHash);
      const oldRootView = new Uint8Array(oldSTH.rootHash);
      const newRootView = new Uint8Array(newSTH.rootHash);

      if((oldHashView.length !== oldRootView.length) ||
        (newHashView.length !== newRootView.length))
        return false;

      for(let i = 0; i < oldHashView.length; i++)
        if(oldHashView[i] !== oldRootView[i])
          return false;

      for(let i = 0; i < newHashView.length; i++)
        if(newHashView[i] !== newRootView[i])
          return false;

      return true;
    });

    return sequence;
  }
}

/**
 * Certificate Transparency Utilities
 * Polyfill loaders
 *
 * By Fotis Loukos <me@fotisl.com>
 */

const engines = {
  fetch: null,
  webcrypto: null
};



function getFetch() {
  return engines.fetch;
}





(function initEngines() {
  if(typeof self !== 'undefined') {
    if('fetch' in self) {
      engines.fetch = self.fetch;
    }

    engines.webcrypto = getEngine().crypto;
  }
})();

/**
 * Certificate Transparency Utilities
 * CTLog class
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

/**
 * An audit proof.
 * @typedef {Object} AuditProof
 * @property {number} index - The index of the leaf in the tree.
 * @property {Array<ArrayBuffer>} auditPath - The audit path.
 */

/**
 * An entry in the log.
 * @typedef {Object} LogEntry
 * @property {MerkleTreeLeaf} leaf - The merkle tree leaf.
 * @property {Array.<pkijs.Certificate>} extraData - The data pertaining to
 * the entry.
 * @property {number} index - The index of the leaf in the tree.
 */

/**
 * An entry in the log and the audit proof.
 * @typedef {Object} LogEntryAndProof
 * @property {MerkleTreeLeaf} leaf - The merkle tree leaf.
 * @property {Array.<pkijs.Certificate>} extraData - The data pertaining to
 * the entry.
 * @property {Array<ArrayBuffer>} auditPath - The audit path.
 * @property {number} index - The index of the leaf in the tree.
 */

/**
 * Load a cert from an offset at an ArrayBuffer, with it's length prepended.
 * @param {ArrayBuffer} buffer - The buffer with the certificate.
 * @param {number} offset - The offset to start looking for the certificate.
 * @return {Object} An object with a length member containing the length of
 * the certificate and a certificate object with the actual certificate.
 */
function extractCert(buffer, offset) {
  const bufferView = new Uint8Array(buffer);

  const length = (bufferView[offset] << 16) +
    (bufferView[offset + 1] << 8) + bufferView[offset + 2];

  let certificate;

  try {
    const asn1 = fromBER(buffer.slice(offset + 3, offset + 3 + length));
    certificate = new Certificate({schema: asn1.result});
  } catch(err) {
    return {
      length,
      certificate: null
    };
  }

  return {
    length,
    certificate
  };
}

/**
 * Parse extraData reply for a Certificate and return the chain.
 * @param {ArrayBuffer} extraData - The extra data.
 * @return {Array.<pkijs.Certificate>} An array of pkijs.Certificates.
 */
function parseCertExtraData(extraData) {
  const extraDataView = new Uint8Array(extraData);

  let offset = 3;
  let certs = [];

  while(offset < extraDataView.length) {
    const res = extractCert(extraData, offset);

    if(res.certificate !== null)
      certs.push(res.certificate);

    offset += (3 + res.length);
  }

  return certs;
}

/**
 * Parse extraData reply for a Precertificate and return the chain.
 * @param {ArrayBuffer} extraData - The extra data.
 * @return {Array.<pkijs.Certificate>} An array of pkijs.Certificates.
 */
function parsePrecertExtraData(extraData) {
  const extraDataView = new Uint8Array(extraData);

  let offset = 0;
  let certs = [];

  let res = extractCert(extraData, offset);
  if(res.certificate !== null)
    certs.push(res.certificate);
  offset += (3 + res.length);

  /* Move on to the chain */
  offset += 3;

  while(offset < extraDataView.length) {
    res = extractCert(extraData, offset);

    if(res.certificate !== null)
      certs.push(res.certificate);

    offset += (3 + res.length);
  }

  return certs;
}

/**
 * CTLog class
 */
class CTLog {
  /**
   * Construct a CTLog object.
   * @param {string} url - The url of the log.
   * @param {ArrayBuffer} pubKey - The public key of the log.
   * @param {number} version - The version of the log.
   * @param {ArrayBuffer} logId - The log id.
   * @param {number} maximumMergeDelay - The maximum merge delay.
   * @param {string} description - The description of the log.
   * @param {Array.<string>} operators - The operators of the log.
   */
  constructor(url, pubKey, version = Version.v1, logId = null,
    maximumMergeDelay = 0, description = null, operators = null) {
    if(version !== Version.v1)
      throw new Error('Unsupported CT version');

    /**
     * @type string
     * @description The url of the log.
     */
    this.url = url;
    /**
     * @type ArrayBuffer
     * @description The public key of the log.
     */
    this.pubKey = pubKey;
    /**
     * @type number
     * @description The version of the log.
     */
    this.version = version;
    /**
     * @type ArrayBuffer
     * @description The log id.
     */
    this.logId = logId;
    /**
     * @type number
     * @description The maximum merge delay.
     */
    this.maximumMergeDelay = maximumMergeDelay;
    /**
     * @type string
     * @description The description of the log.
     */
    this.description = description;
    /**
     * @type Array<string>
     * @description The operators of the log.
     */
    this.operators = operators;
  }

  /**
   * Generate the log id from the public key.
   * @param {string} algorithmOID - The OID of the algorithm used for signing.
   * If this is null, then a heuristic method based on the key size will
   * be used.
   * @return {Promise.<Boolean>} The result of the generation. This will
   * normally be true, and it's used to notify that the calculation has
   * finished.
   */
  generateId(algorithmOID = null) {
    let algorithmIdentifier;

    if(algorithmOID === null) {
      if(this.pubKey.byteLength === 91) {
        algorithmIdentifier = new AlgorithmIdentifier({
          algorithmId: '1.2.840.10045.2.1'
        });
      } else if(this.pubKey.byteLength === 294) {
        algorithmIdentifier = new AlgorithmIdentifier({
          algorithmId: '1.2.840.113549.1.1.1'
        });
      } else {
        return Promise.reject(new Error('Cannot identify algorithm'));
      }
    } else {
      algorithmIdentifier = new AlgorithmIdentifier({
        algorithmId: algorithmOID
      });
    }

    const pubKeyInfo = new PublicKeyInfo({
      algorithm: algorithmIdentifier,
      subjectPublicKey: new BitString({
        valueHex: this.pubKey
      })
    });

    return getEngine().subtle.digest({
      name: 'SHA-256'
    }, pubKeyInfo.subjectPublicKey.valueBlock.valueHex).then(id => {
      this.logId = id;

      return true;
    });
  }

  /**
   * Get the base url under which all calls are made.
   * @return {string} The base url
   */
  getBaseUrl() {
    let url;

    if(this.url.startsWith('https://'))
      url = this.url;
    else
      url = 'https://' + this.url;

    while(url.endsWith('/'))
      url = url.substr(0, url.length - 1);

    if(this.version === Version.v1)
      url = url + '/ct/v1';

    return url;
  }

  /**
   * Add a certificate.
   * @param {Array.<pkijs.Certificate>} certs - A list of certificates. The
   * first certificate is the end-entity certificate to be added, the second
   * chains to the first and so on (please check RFC6962 section 4.1).
   * @return {Promise.<SignedCertificateTimestamp>} A promise that is resolved
   * with the SCT.
   */
  addCertChain(certs) {
    const encCerts = [];

    certs.forEach(cert => {
      const schema = cert.toSchema().toBER(false);
      encCerts.push(toBase64(arrayBufferToString(schema)));
    });

    let sequence = getFetch()(this.getBaseUrl() + '/add-chain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chain: encCerts
      })
    });

    sequence = sequence.then(res => {
      if(!res.ok)
        return Promise.reject(new Error(`Error: ${res.statusText}`));
      return res.json();
    });

    sequence = sequence.then(res => {
      const logId = stringToArrayBuffer(fromBase64(res.id));
      const extensions = stringToArrayBuffer(
        fromBase64(res.extensions));
      const signature = stringToArrayBuffer(
        fromBase64(res.signature));

      return new SignedCertificateTimestamp(res.sct_version, logId,
        res.timestamp, extensions, signature, LogEntryType.x509_entry,
        certs[0].toSchema().toBER(false));
    });

    return sequence;
  }

  /**
   * Add a precertificate.
   * @param {Array.<pkijs.Certificate>} precerts - A list of certificates. The
   * first should be the precertificate to be added, the second chains to
   * the first and so on (please check RFC6962 section 4.1).
   * @return {Promise.<SignedCertificateTimestamp>} A promise that is resolved
   * with the SCT.
   */
  addPreCertChain(certs) {
    const encCerts = [];

    certs.forEach(cert => {
      const schema = cert.toSchema().toBER(false);
      encCerts.push(toBase64(arrayBufferToString(schema)));
    });

    let sequence = getFetch()(this.getBaseUrl() + '/add-pre-chain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chain: encCerts
      })
    });

    sequence = sequence.then(res => {
      if(!res.ok)
        return Promise.reject(new Error(`Error: ${res.statusText}`));
      return res.json();
    });

    sequence = sequence.then(res => {
      const logId = stringToArrayBuffer(fromBase64(res.id));
      const extensions = stringToArrayBuffer(
        fromBase64(res.extensions));
      const signature = stringToArrayBuffer(
        fromBase64(res.signature));

      return new SignedCertificateTimestamp(res.sct_version, logId,
        res.timestamp, extensions, signature, LogEntryType.precert_entry,
        certs[0].toSchema().toBER(false));
    });

    return sequence;
  }

  /**
   * Get the SignedTreeHead.
   * @return {Promise.<SignedTreeHead>} A promise that is resolved with the
   * SignedTreeHead.
   */
  getSTH() {
    let sequence = getFetch()(this.getBaseUrl() + '/get-sth');

    sequence = sequence.then(res => {
      if(!res.ok)
        return Promise.reject(new Error(`Error: ${res.statusText}`));
      return res.json();
    });

    sequence = sequence.then(res => {
      const rootHash = stringToArrayBuffer(
        fromBase64(res.sha256_root_hash));
      const signature = stringToArrayBuffer(
        fromBase64(res.tree_head_signature));

      return new SignedTreeHead(res.tree_size, res.timestamp, rootHash,
        signature, Version.v1);
    });

    return sequence;
  }

  /**
   * Get the consistency proof between two signed tree heads.
   * @param {(number|SignedTreeHead)} first - The first signed tree head or its
   * size.
   * @param {(number|SignedTreeHead)} second - The second signed tree head or
   * its size.
   * @return {Promise.<Array<ArrayBuffer>>} A Promise than is resolved with an
   * array of ArrayBuffers containing the proofs.
   */
  getSTHConsistency(first, second) {
    let firstSize, secondSize;

    if(first instanceof SignedTreeHead) {
      firstSize = first.treeSize;
    } else if(typeof first === 'number') {
      firstSize = first;
    } else {
      return Promise.reject(new Error('Unknown first head type'));
    }

    if(second instanceof SignedTreeHead) {
      secondSize = second.treeSize;
    } else if(typeof second === 'number') {
      secondSize = second;
    } else {
      return Promise.reject(new Error('Unknown second head type'));
    }

    const params = {
      first: firstSize,
      second: secondSize
    };

    const url = this.getBaseUrl() + '/get-sth-consistency?' +
      paramsToQueryString(params);

    let sequence = getFetch()(url).then(res => {
      if(!res.ok)
        return Promise.reject(new Error(`Error: ${res.statusText}`));
      return res.json();
    });

    sequence = sequence.then(res => {
      const cons = [];

      for(let proof of res.consistency)
        cons.push(stringToArrayBuffer(fromBase64(proof)));

      return cons;
    });

    return sequence;
  }

  /**
   * Get merkle audit proof by leaf hash.
   * @param {(number|SignedTreeHead)} sth - The signed tree head or the tree
   * size on which to base the proof.
   * @param {ArrayBuffer} hash - The leaf hash.
   * @return {Promise.<AuditProof>} A promise that is resolved with the audit
   * proof.
   */
  getProofByHash(sth, hash) {
    let treeSize;

    if(sth instanceof SignedTreeHead) {
      treeSize = sth.treeSize;
    } else if(typeof sth === 'number') {
      treeSize = sth;
    } else {
      return Promise.reject(new Error('Unknown signed tree head type'));
    }

    const params = {
      tree_size: treeSize,
      hash: toBase64(arrayBufferToString(hash))
    };

    const url = this.getBaseUrl() + '/get-proof-by-hash?' +
      paramsToQueryString(params);

    let sequence = getFetch()(url).then(res => {
      if(!res.ok)
        return Promise.reject(new Error(`Error: ${res.statusText}`));
      return res.json();
    });

    sequence = sequence.then(res => {
      const auditPath = [];
      res.audit_path.forEach(p => {
        auditPath.push(stringToArrayBuffer(fromBase64(p)));
      });
      return {
        index: res.leaf_index,
        auditPath
      };
    });

    return sequence;
  }

  /**
   * Get merkle audit proof by leaf hash.
   * @param {(number|SignedTreeHead)} sth - The signed tree head or the tree
   * size on which to base the proof.
   * @param {MerkleTreeLeaf} leaf - The merkle tree leaf.
   * @return {Promise.<AuditProof>} A promise that is resolved with the audit
   * proof.
   */
  getProofByLeaf(sth, leaf) {
    return leaf.getHash().then(h => this.getProofByHash(sth, h));
  }

  /**
   * Get entries from the log.
   * @param {number} start - The index of the first entry.
   * @param {number} end - The index of the last entry.
   * @return {Promise.<Array<LogEntry>>} A promise that is resolved with an
   * array of MerkleTreeLeaf structures.
   */
  getEntries(start, end) {
    const params = {
      start,
      end
    };

    const url = this.getBaseUrl() + '/get-entries?' +
      paramsToQueryString(params);

    let sequence = getFetch()(url).then(res => {
      if(!res.ok)
        return Promise.reject(new Error(`Error: ${res.statusText}`));
      return res.json();
    });

    sequence = sequence.then(res => {
      const entries = [];

      for(let i = 0; i < res.entries.length; i++) {
        const entry = res.entries[i];
        const leafData = stringToArrayBuffer(fromBase64(
          entry.leaf_input));
        const leaf = MerkleTreeLeaf.fromBinary(leafData);
        let extraData;
        if(leaf.timestampedEntry.type === LogEntryType.x509_entry)
          extraData = parseCertExtraData(stringToArrayBuffer(
            fromBase64(entry.extra_data)));
        else
          extraData = parsePrecertExtraData(stringToArrayBuffer(
            fromBase64(entry.extra_data)));

        entries.push({
          leaf,
          extraData,
          index: start + i
        });
      }

      return entries;
    });

    return sequence;
  }

  /**
   * Get accepted roots.
   * @return {Promise.<Array<pkijs.Certificate>>} An array of certificates.
   */
  getRoots() {
    let sequence = getFetch()(this.getBaseUrl() + '/get-roots');

    sequence = sequence.then(res => {
      if(!res.ok)
        return Promise.reject(new Error(`Error: ${res.statusText}`));
      return res.json();
    });

    sequence = sequence.then(res => {
      const certs = [];

      res.certificates.forEach(cert => {
        const certData = stringToArrayBuffer(fromBase64(cert));
        const asn1 = fromBER(certData);
        certs.push(new Certificate({ schema: asn1.result }));
      });

      return certs;
    });

    return sequence;
  }

  /**
   * Get an entry from the log and the audit path.
   * @param {(number|SignedTreeHead)} sth - The signed tree head or the tree
   * size on which to base the proof.
   * @param {number} index - The index of the entry.
   * @return {Promise.<LogEntryAndProof>} The log entry with the audit path.
   */
  getEntryAndProof(sth, index) {
    let treeSize;

    if(sth instanceof SignedTreeHead) {
      treeSize = sth.treeSize;
    } else if(typeof sth === 'number') {
      treeSize = sth;
    } else {
      return Promise.reject(new Error('Unknown signed tree head type'));
    }

    const params = {
      leaf_index: index,
      tree_size: treeSize
    };

    const url = this.getBaseUrl() + '/get-entry-and-proof?' +
      paramsToQueryString(params);

    let sequence = getFetch()(url).then(res => {
      if(!res.ok)
        return Promise.reject(new Error(`Error: ${res.statusText}`));
      return res.json();
    });

    sequence = sequence.then(res => {
      const leafData = stringToArrayBuffer(fromBase64(
        res.leaf_input));
      const leaf = MerkleTreeLeaf.fromBinary(leafData);
      let extraData;
      if(leaf.timestampedEntry.type === LogEntryType.x509_entry)
        extraData = parseCertExtraData(stringToArrayBuffer(
          fromBase64(res.extra_data)));
      else
        extraData = parsePrecertExtraData(stringToArrayBuffer(
          fromBase64(res.extra_data)));
      const auditPath = [];

      res.audit_path.forEach(p => {
        auditPath.push(stringToArrayBuffer(fromBase64(p)));
      });

      return {
        leaf,
        extraData,
        auditPath,
        index
      };
    });

    return sequence;
  }
}

/**
 * Certificate Transparency Utilities
 * CTLogHelper class
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

/**
 * CTLogHelper class
 */
class CTLogHelper {
  /**
   * Construct a CTLog helper object.
   */
  constructor(logs = []) {
    /**
     * @type Array.<CTLog>
     * @description An array of all logs stored.
     */
    this.logs = logs;
  }

  /**
   * Fetch all logs from a url based on the standard google json schema.
   * @param {string} url - The url to fetch logs from.
   * @return {Promise.<Boolean>} A Promise that is resolved with the result of
   * the file parsing.
   */
  fetch(url) {
    return getFetch()(url).then(res => {
      if(!res.ok)
        return Promise.reject(new Error(`Error: ${res.statusText}`));
      return res.json();
    }).then(res => {
      let ret = true;
      let operatorList = {};

      if(!('operators' in res) || !('logs' in res))
        return false;

      res.operators.forEach(operator => {
        if(!('id' in operator) || !('name' in operator)) {
          ret = false;
          return;
        }
        operatorList[operator['id']] = operator['name'];
      });

      if(!ret)
        return ret;

      let logs = [];
      res.logs.forEach(log => {
        if(!('url' in log) || !('key' in log) ||
          !('description' in log) || !('operated_by' in log) ||
          !('maximum_merge_delay' in log)) {
          ret = false;
          return;
        }

        const pubKey = stringToArrayBuffer(fromBase64(log.key));
        let logId = null;
        if('log_id' in log)
          logId = stringToArrayBuffer(fromBase64(log.log_id));

        let operators = [];
        log.operated_by.forEach(operator => {
          operators.push(operatorList[operator]);
        });

        logs.push(new CTLog(log.url, pubKey, Version.v1, logId,
          log.maximum_merge_delay, log.description, operators));
      });

      if(ret)
        this.logs.push(...logs);

      return ret;
    });
  }

  /**
   * Find a log based on its id.
   * @param {ArrayBuffer} logId - The log's id.
   * @return {CTLog} The CT log or null if it cannot be found.
   */
  findById(logId) {
    const searchLogIdView = new Uint8Array(logId);

    for(const log of this.logs) {
      if(log.logId === null)
        continue;
      const logIdView = new Uint8Array(log.logId);

      let i;
      for(i = 0; i < logIdView.length; i++)
        if(logIdView[i] !== searchLogIdView[i]) {
          break;
        }

      if(i === logIdView.length)
        return log;
    }

    return null;
  }

  /**
   * Generate ids for all logs.
   * Since different logs may use different algorithms, the algorithm for
   * every log is heuristically determined. If you need to specify the
   * algorithm yourself, you can use the generateId() method of every CTLog.
   * @return {Promise.<Boolean>} The result of the generation. This will
   * normally be true, and it's used to notify that the calculation has
   * finished.
   */
  generateIds() {
    const generations = [];

    this.logs.forEach(log => {
      generations.push(log.generateId());
    });

    return Promise.all(generations).then(res => {
      let ret = true;

      res.forEach(r => {
        ret &= r;
      });

      return ret;
    });
  }

  /**
   * Find a log by url.
   * @param {string} url - The log's url.
   * @return {CTLog} The log or null if it cannot be found.
   */
  findByUrl(url) {
    let search = url;

    if(search.startsWith('https://'))
      search = search.substr(8);

    while(search.endsWith('/'))
      search = search.substr(0, search.length - 1);

    for(const log of this.logs) {
      let match = log.url;

      if(match.startsWith('https://'))
        match = match.substr(8);

      while(match.endsWith('/'))
        match = match.substr(0, match.length - 1);

      if(search === match)
        return log;
    }

    return null;
  }

  /**
   * Find a log by description.
   * The search is case insensitive and searches for if the string is part of
   * the log description. If multiple logs match the description, only the first
   * will be returned.
   * @param {string} description - The description that will be used for
   * matching.
   * @return {CTLog} The log or null if it cannot be found.
   */
  findByDescription(description) {
    for(const log of this.logs) {
      if(log.url.toLowerCase().includes(description.toLowerCase()))
        return log;
    }

    return null;
  }
}

CTLogHelper.lists = {
  googleCT: 'https://www.gstatic.com/ct/log_list/log_list.json',
  googleCTAll: 'https://www.gstatic.com/ct/log_list/all_logs_list.json',
  googleChromium: 'https://chromium.googlesource.com/chromium/src/+/master' +
    '/components/certificate_transparency/data/log_list.json?format=TEXT',
  apple: 'https://opensource.apple.com/source/security_certificates/security' +
    '_certificates-55093.40.3/certificate_transparency/log_list.json'
};

/**
 * Certificate Transparency Utilities
 * PreCert class
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

/**
 * PreCert class
 * Please note that this is a precert as defined in section 3.2 of RFC6962
 * and not a certificate with the poison extension.
 */

/**
 * Certificate Transparency Utilities
 * CertHelper class
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

/**
 * Certificate Transparency Utilities
 * CompactMerkleTree class
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

/**
 * CompactMerkleTree class
 * In this specific case, all nodes are considered as hashes.
 */
class CompactMerkleTree {
  /**
   * Construct a CompactMerkleTree.
   * This is used for validating trees.
   */
  constructor() {
    /**
     * @type {Array.<ArrayBuffer>}
     * @description The nodes in the CMT.
     */
    this.nodes = [];
    /**
     * @type {number}
     * @description The size of the full tree this CMT corresponds to.
     */
    this.size = 0;
    /**
     * @type {number}
     * @description The levels of the tree.
     */
    this.levels = 0;
  }

  /**
   * Initialize the tree.
   * You can get the leftNodes and the rightNode by getting the entry and proof
   * for the last node when getting a Signed Tree Head. If there are any nodes,
   * they are removed.
   * @param {ArrayBuffer} root - The root.
   * @param {Array.<ArrayBuffer>} leftNodes - The left side nodes of the tree.
   * @param {ArrayBuffer} rightNode - The rightmost node of the tree.
   * @param {number} size - The size of the full tree this CMT corresponds to.
   * @return {Promise.<Boolean>} - A Promise that resolves with the result of
   * the initialization. Errors will be thrown as exceptions, so for the moment
   * this just returns the result of the validation of the root.
   */
  async init(root, leftNodes, rightNode, size) {
    this.nodes = [];
    this.size = size;
    if(this.size === 0) {
      this.levels = 0;
      return;
    }
    this.levels = Math.ceil(Math.log2(size));

    let level = 0;
    let it = 0;
    let prevSize = size - 1;
    for(; prevSize !== 0; prevSize >>= 1) {
      if((prevSize & 1) !== 0) {
        this.nodes[level] = leftNodes[it];
        it++;
      }
      level++;
    }

    if(it !== leftNodes.length)
      throw new Error('Invalid number of leftNodes');

    const rightNodeHash = await rightNode.getHash();
    await this.pushBack(rightNodeHash, 0);
    const verifyRoot = await this.calculateRoot();

    const rootView = new Uint8Array(root);
    const verifyRootView = new Uint8Array(verifyRoot);

    if(rootView.length !== verifyRootView.length)
      return false;

    for(let i = 0; i < rootView.length; i++) {
      if(rootView[i] !== verifyRootView[i])
        return false;
    }

    return true;
  }

  /**
   * Get the hash of two nodes.
   * @param {ArrayBuffer} node1 - The first node.
   * @param {ArrayBuffer} node2 - The second node.
   * @return {Promise.<ArrayBuffer>} A promise that is resolved with the hash.
   */
  hashNodes(node1, node2) {
    const node1View = new Uint8Array(node1);
    const node2View = new Uint8Array(node2);
    const data = new ArrayBuffer(1 + node1View.length + node2View.length);
    const dataView = new Uint8Array(data);
    const webcrypto = getEngine();

    dataView[0] = 0x01;
    dataView.set(node1View, 1);
    dataView.set(node2View, 1 + node1View.length);

    return webcrypto.subtle.digest({ name: 'SHA-256' }, data);
  }

  /**
   * Push a node at a specific level.
   * @param {ArrayBuffer} node - The node to push. This has to be a hash.
   * @param {number} level - The level where to push it at.
   * @return {Promise.<Boolean>} A promise that is resolved with the result of
   * the operation. This is always true, but it is used since if we need to hash
   * something, we have an asynchronous operation.
   */
  pushBack(node, level) {
    if(this.nodes.length <= level) {
      this.nodes.push(node);
      return Promise.resolve(true);
    } else if(typeof this.nodes[level] === 'undefined') {
      this.nodes[level] = node;
      return Promise.resolve(true);
    } else {
      return this.hashNodes(this.nodes[level], node).then(hash =>
        this.pushBack(hash, level + 1)
      ).then(res => {
        if(res === true)
          delete this.nodes[level];
        return res;
      })
    }
  }

  /**
   * Add a new leaf.
   * @param {MerkleTreeLeaf} leaf - The leaf to add.
   * @return {Promise.<Boolean>} A promise that is resolved with the result of
   * the operation. This is always true, but it is used since if we need to hash
   * something, we have an asynchronous operation.
   */
  async addLeaf(leaf) {
    const leafHash = await leaf.getHash();

    return this.pushBack(leafHash, 0).then(result => {
      if(result) {
        this.size++;
        /**
         * If this.size - 1 is a power of 2, then this means we added a new
         * level.
         */
        if(((this.size - 1) & (this.size - 2)) === 0)
          this.levels++;
      }

      return result;
    });
  }

  /**
   * Calculate the current root.
   * @return {Promise.<ArrayBuffer>} A promise that is resolved with the current
   * root hash.
   */
  async calculateRoot() {
    let rightSibling = null;

    for(let level = 0; level < this.levels; level++) {
      if(typeof this.nodes[level] !== 'undefined') {
        if(rightSibling == null)
          rightSibling = this.nodes[level];
        else
          rightSibling = await this.hashNodes(this.nodes[level], rightSibling);
      }
    }

    return rightSibling;
  }
}

/**
 * Certificate Transparency Utilities
 * CTMonitor class
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

/**
 * A callback that is provided with the results of a verification.
 * @callback sthVerificationCallback
 * @param {Boolean} The result of the verification.
 * @param {SignedTreeHead} The first STH used for the verification.
 * @param {SignedTreeHead} The second STH used for the verification.
 */

/**
 * A callback that is provided with a series of certificates.
 * @callback certsCallback
 * @param {Array.<LogEntry>} The certificates.
 */

/**
 * Return the value of a parameter or the default value if one has not been
 * specified.
 * @param {Array} opts - An array with all parameters.
 * @param {string} key - The parameter needed.
 * @return The value of the parameter.
 */
function getParameter(opts, key) {
  if(key in opts)
    return opts[key];

  switch(key) {
    case 'timerInterval':
      return 10000;
    case 'verifySTHConsistency':
      return false;
    case 'verifySTHConsistencyCallback':
      return (result, oldSTH, newSTH) => {};
    case 'fetchNewCertificates':
      return false;
    case 'fetchNewCertificatesCallback':
      return (certs) => {};
    case 'verifyTree':
      return false;
    case 'verifyTreeCallback':
      return (result, oldSTH, newSTH) => {};
    default:
      return null;
  }
}

/**
 * CTMonitor class
 */
class CTMonitor {
  /**
   * Construct a CTMonitor.
   * @param {CTLog} log - The log to be monitored.
   * @param {Array} opts - The options for the monitor. Please see the members
   * of this class to find the various options.
   */
  constructor(log, opts = {}) {
    /**
     * @type {CTLog}
     * @description The log.
     */
    this.log = log;
    /**
     * @type {SignedTreeHead}
     * @description The previous STH.
     */
    this.previousSTH = null;
    /**
     * @type {number}
     * @description The timer used to check for a new STH.
     */
    this.timer = null;
    /**
     * @type {number}
     * @description The interval between checking for a new STH.
     */
    this.timerInterval = getParameter(opts, 'timerInterval');
    /**
     * @type {Boolean}
     * @description Verify the consistency of the new STH.
     */
    this.verifySTHConsistency = getParameter(opts, 'verifySTHConsistency');
    /**
     * @type {sthVerificationCallback}
     * @description Verification consistency callback.
     */
    this.verifySTHConsistencyCallback = getParameter(opts,
      'verifySTHConsistencyCallback');
    /**
     * @type {Boolean}
     * @description Fetch new certificates.
     */
    this.fetchNewCertificates = getParameter(opts, 'fetchNewCertificates');
    /**
     * @type {certsCallback}
     * @description Certificates fetching callback.
     */
    this.fetchNewCertificatesCallback = getParameter(opts,
      'fetchNewCertificatesCallback');
    /**
     * @type {Boolean}
     * @description Verify the new tree. In effect, this verifies that the new
     * entries with the old STH generate the new STH. If this is set to true,
     * then verifySTHConsistency need not be set since it is tested here too.
     */
    this.verifyTree = getParameter(opts, 'verifyTree');
    /**
     * @type {sthVerificationCallback}
     * @description Tree verification callback.
     */
    this.verifyTreeCallback = getParameter(opts, 'verifyTreeCallback');
  }

  /**
   * Start monitoring.
   */
  start() {
    this.log.getSTH().then(sth => {
      this.previousSTH = sth;
      this.timer = setInterval(this.monitorChange.bind(this), this.timerInterval);
    });
  }

  /**
   * Stop monitoring
   */
  stop() {
    clearInterval(this.timer);
  }

  /**
   * Monitor for any changes.
   */
  async monitorChange() {
    const newSTH = await this.log.getSTH();

    if(this.previousSTH.treeSize === newSTH.treeSize)
      return;

    if(this.verifySTHConsistency) {
      const proofs = await this.log.getSTHConsistency(this.previousSTH,
        newSTH);
      const result = await this.previousSTH.verifyConsistency(newSTH, proofs);
      this.verifySTHConsistencyCallback(result, this.previousSTH, newSTH);
    }

    let certs = [];
    if(this.fetchNewCertificates || this.verify) {
      let start = this.previousSTH.treeSize;
      let end = newSTH.treeSize - 1;
      let left = end - start + 1;

      while(left > 0) {
        const newCerts = await this.log.getEntries(end - left + 1, end);
        certs = certs.concat(newCerts);
        left -= newCerts.length;
      }
    }

    if(this.fetchNewCertificates)
      this.fetchNewCertificatesCallback(certs);

    if(this.verifyTree) {
      const lastEntryAndProof = await this.log.getEntryAndProof(
        this.previousSTH, this.previousSTH.treeSize - 1);
      const auditPath = lastEntryAndProof.auditPath;
      const node = lastEntryAndProof.leaf;

      const cmt = new CompactMerkleTree();

      let res = await cmt.init(this.previousSTH.rootHash, auditPath, node,
        this.previousSTH.treeSize);

      if(res === false) {
        this.verifyTreeCallback(false, this.previousSTH, newSTH);
      } else {
        for(let i = 0; i < certs.length; i++)
          await cmt.addLeaf(certs[i].leaf);

        const verifyRoot = await cmt.calculateRoot();
        const newRootView = new Uint8Array(newSTH.rootHash);
        const verifyRootView = new Uint8Array(verifyRoot);

        if(newRootView.length !== verifyRootView.length) {
          this.verifyTreeCallback(false, this.previousSTH, newSTH);
        } else {
          let idx = 0;
          for(idx = 0; idx < newRootView.length; idx++) {
            if(newRootView[idx] !== verifyRootView[idx]) {
              this.verifyTreeCallback(false, this.previousSTH, newSTH);
              break;
            }
          }
          if(idx === newRootView.length)
            this.verifyTreeCallback(true, this.previousSTH, newSTH);
        }
      }
    }

    this.previousSTH = newSTH;
  }

  /**
   * Verify the whole tree of a log.
   * Warning: this will download all entries from the log, and thus can
   * generate a lot of traffic.
   * @param {CTLog} log - The CT log.
   * @param {Promise.<Boolean>} A Promise that resolves with the result of the
   * validation.
   */
  static async verifyFullTree(log) {
    const sth = await log.getSTH();

    /**
     * There is no need to initialize the CMT with init() since there are no
     * nodes in the actual tree at this time.
     */
    const cmt = new CompactMerkleTree();

    let end = sth.treeSize - 1;
    let left = sth.treeSize;

    while(left > 0) {
      const newCerts = await log.getEntries(end - left + 1, end);

      for(let i = 0; i < newCerts.length; i++) {
        let res = await cmt.addLeaf(newCerts[i].leaf);

        if(res === false)
          return false;
      }

      left -= newCerts.length;
    }

    const rootView = new Uint8Array(sth.rootHash);
    const verifyRoot = await cmt.calculateRoot();
    const verifyRootView = new Uint8Array(verifyRoot);

    if(rootView.length !== verifyRootView.length)
      return false;

    for(let i = 0; i < rootView.length; i++)
      if(rootView[i] !== verifyRootView[i])
        return false;

    return true;
  }
}

/**
 * Certificate Transparency Utilities
 *
 * By Fotis Loukos <me@fotisl.com>
 * @module ctutils
 */

const typemap = {
  '2.5.4.6': 'countryName',
  '2.5.4.11': 'organizationalUnitName',
  '2.5.4.10': 'organizationName',
  '2.5.4.3': 'commonName',
  '2.5.4.7': 'localityName',
  '2.5.4.8': 'stateOrProvinceName',
  '2.5.4.12': 'title',
  '2.5.4.42': 'givenName',
  '2.5.4.43': 'initials',
  '2.5.4.4': 'surname',
  '1.2.840.113549.1.9.1': 'emailAddress',
  '2.5.4.15': 'businessCategory',
  '1.3.6.1.4.1.311.60.2.1.1': 'jurisdictionLocalityName',
  '1.3.6.1.4.1.311.60.2.1.2': 'jurisdictionStateOrProvinceName',
  '1.3.6.1.4.1.311.60.2.1.3': 'jurisdictionCountryName',
  '2.5.4.5': 'serialNumber',
  '2.5.4.9': 'streetAddress',
  '2.5.4.17': 'postalCode',
  '2.5.4.45': 'uniqueIdentifier'
};

function rdnToText(rdn) {
  let subj = '';

  for(let i = 0; i < rdn.typesAndValues.length; i++) {
    let tv = rdn.typesAndValues[i];
    let type = typemap[tv.type];

    if(typeof type === 'undefined')
      type = tv.type;

    subj += (type + '=' + tv.value.valueBlock.value);
    if(i !== (rdn.typesAndValues.length - 1))
      subj += ', ';
  }

  return subj;
}

function certToPEM(cert) {
  let b64 = toBase64(arrayBufferToString(
    cert.toSchema().toBER(false)));

  let pem = '-----BEGIN CERTIFICATE-----\n';
  while(b64.length > 64) {
    pem += b64.substr(0, 64);
    pem += '\n';
    b64 = b64.substr(64);
  }
  pem += b64;
  pem += '\n-----END CERTIFICATE-----\n';

  return pem;
}

function getLogs() {
  const logHelper = new CTLogHelper();
  return logHelper.fetch(CTLogHelper.lists.googleCT).then(res => {
    return logHelper.generateIds();
  }).then(res => {
    let logs = [];

    logHelper.logs.forEach(log => {
      logs.push({
        url: log.url,
        pubkey: toBase64(arrayBufferToString(log.pubKey)),
        version: log.version,
        logid: toBase64(arrayBufferToString(log.logId)),
        description: log.description,
        operators: log.operators.join(', ')
      });
    });

    return logs;
  });
}

function getMonitor(opts) {
  const log = new CTLog(opts.url, stringToArrayBuffer(
    fromBase64(opts.pubkey)), opts.version, stringToArrayBuffer(
    fromBase64(opts.logid)), 0, opts.description);

  const monitor = new CTMonitor(log, {
    timerInterval: opts.update * 1000,
    fetchNewCertificates: true,
    fetchNewCertificatesCallback: entries => {
      let certs = [];

      entries.forEach(entry => {
        const leaf = entry.leaf;
        const timestampedEntry = leaf.timestampedEntry;
        let cert;

        if(timestampedEntry.type === LogEntryType.x509_entry) {
          const asn1 = fromBER(timestampedEntry.cert);
          cert = new Certificate({schema: asn1.result});
        } else {
          cert = entry.extraData[0];
        }

        certs.push({
          subject: rdnToText(cert.subject),
          pem: certToPEM(cert),
          filename: entry.index.toString() + '.pem'
        });
      });

      opts.callback(certs);
    }
  });

  return monitor;
}

exports.getLogs = getLogs;
exports.getMonitor = getMonitor;

return exports;

}({}));
