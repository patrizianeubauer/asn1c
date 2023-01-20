//
// Created by Patrizia Neubauer on 11.08.22.
//
// Description: Parsing ASN1-Files to ROS messages.
// TBA
//
// Author(s): "Patrizia Neubauer"
// Copyright: "Copyright 2022, VIF V2X Platform Project"
// Credits: [""]
// E-Mail: "patrizia.neubauer@v2c2.at"
//
// Possible Improvements:
// [] At the current stage, the program creates a new file, if there are no brackets after the expression, even if the expressions should be in one file. (I.e. RegionId, noRegion, addGrpA, addGrpB, addGrpC, DSRCmsgID)
// [] File handling of duplicates (file name twice in two different folder).
// [] Format templates (I.e. REG-EXT-...) are generated at the moment. (maybe error in ROS2?)
// [] DDD-IO-LIST: sequenceof-format does not work yet for '-' splitting.
// [] unit Code-Units (2..4 | 6..8) --> ValueError: the constants iterable contains duplicate names.

#ifndef ASN_1_C_FORK_ASN1ROSPARSER_H
#define ASN_1_C_FORK_ASN1ROSPARSER_H

#include <stdbool.h>

enum asn1write_flags {
    APF_WRITE_ROS_MESSAGE	= 0x16,	/* Generate ROS Message */
};

static abuf all_output_;
static char dataTypeHelp[100];
static bool check = true;
static char identifierHelp[1000];
static asn1p_expr_t *tcHelp;
static int containerCount = 0;
static bool choiceCheck = false;
static char containerText[100000];
static char everythingText[100000];
static char identifierForContainer[100];
static char identifierForSequenceRegion[100];
static char identifierForRegChoice[100];
static char dirPath[150];
static char fileName [10000];
static int counterEnumerated = 0;
static bool choiceEnd = false;
static bool sequenceEnd = false;
static bool checkAllUpper = false;
static char followingTextSequenceOf[10000];
static bool isSequenceOf = false;

struct counter {
    int index;
    int namesCounter;
};

struct identifierValueNode {
    char * identifier;
    char * value;
};

int asn1write(asn1p_t *asn, enum asn1write_flags flags, char * path);
const char *asn1p_constraint_string(const asn1p_constraint_t *ct);
static int asn1write_module(asn1p_t *asn, asn1p_module_t *mod, enum asn1write_flags flags);

/**
 * An if-statement was added to check if the reference contains a '-'.
 * This character is going to be replaced with '_' and after that the reference will be added to the summary text char array.
 * @param ref
 * @param flags
 * @param level
 * @return
 */
static int asn1write_ref(const asn1p_ref_t *ref, enum asn1write_flags flags, int level);

/**
 * An if-statement was added to check if the reference contains a '-'.
 * This character is going to be replaced with '_'.
 * The first character has to be uppercase, if not it will be converted to uppercase letters.
 * After that the reference will be added to the container text char array.
 * @param ref
 * @param flags
 * @param level
 * @return
 */
static int asn1write_ref_container(const asn1p_ref_t *ref, enum asn1write_flags flags, int level);

/**
 * Here, all the components of the reference are being formatted properly and made uppercase:
 * - If the character is '-' or '_', '_' will be added to the char array.
 * - If there is a lowercase letter in front of an uppercase letter, '_' will be added in between them.
 * - Else the character will be added unchanged.
 * After all the queries, the whole char array will be converted to uppercase.
 * After that the formatted char array will be added to the summary text char array.
 * This method is used, when you don't want your static variables to change its values, because
 * it only adds the needed reference in the correct format.
 * @param ref
 * @param flags
 * @param level
 * @return
 */
static int asn1write_ref_toUpperForEverythingText(const asn1p_ref_t *ref, enum asn1write_flags flags, int level);

/**
 * Here, a method is called for the reference char array. In the called method the array
 * is going to be transformed to uppercase with '_' in between the words and it will be concatenated to the summary text char array as well.
 * This method is used, when the changed static variable for the identifier is going to be used for further formatting.
 * @param ref
 * @param flags
 * @param level
 * @return
 */
static int asn1write_ref_toUpperWithFormat(const asn1p_ref_t *ref, enum asn1write_flags flags, int level);

/**
 * Added that the arguments are concatenated to the summary text char array.
 * @param pl
 * @param flags
 * @return
 */
static int asn1write_params(const asn1p_paramlist_t *pl, enum asn1write_flags flags);

/**
 * In this method all types of the constraints are being handled separately.
 * - If the constraint type is "ACT_EL_TYPE", its value will be concatenated to the summary text char array.
 * - If the constraint type is "ACT_EL_VALUE" its value will also be concatenated, an exception is made when the actual data type
 *   is type "OCTET STRING". There has to be a "1.." before the single number.
 * - If the constraint type is "ACT_EL_ULRANGE", it'll be checked whether the actual data type is "SEQUENCE OF"
 *   or "OCTET STRING". If this is not the case, there has to be "Identifier_RANGE_MIN" and "Identifier_RANGE_MAX" added in front of the range values.
 *   In the other case, the range values are being concatenated with ".." in between.
 * - If the constraint type is "ACT_CT_FROM" and afterwards "ACT_CT_SIZE" and the data type is "SEQUENCE OF" or
 *   "OCTET STRING", "#size(" and the values with "..." in between them, will be added to the summary text char array.
 * @param asn1p_expr_s
 * @return
 */
static int asn1write_constraint(char *asn1p_expr_s, const asn1p_constraint_t *, enum asn1write_flags);

/**
 * Added the concatenation of each asn1p_value_t type.
 * - Important here is the special handling of the type "ATV_UNPARSED". "RegularExtensions" are being handled in a unique way.
 * @param val
 * @param flags
 * @return
 */
static int asn1write_value(const asn1p_value_t *val, enum asn1write_flags flags);

/**
 * In this method a few types of expressions are being handled separately.
 * If the level is 0 or 1 and the identifier has been set:
 * - If the marker flag has the value "EM_OPTIONAL", the "# OPTIONAL FIELD..."-text will be added above the expression.
 * - If the expression type is "A1TC_UNIVERVAL" and the current data type is "bool",
 *   "bool" will be added in front of the formatted ROS2 expression.
 * - If the expression type is "A1TC_UNIVERVAL" and the current data type is "string",
 *   "string" will be added in front of the formatted ROS2 expression.
 * - If the expression type is "A1TC_UNIVERVAL" and the current data type is "integer",
 *   "uint64" will be added in front of the formatted ROS2 expression.
 * - If the expression type is "A1TC_UNIVERVAL" and the current data type is "enumerated",
 *   "uint64" will be added in front of the formatted ROS2 expression.
 *   Additionally, a counter number will ne concatenated at the end.
 * - If the expression type is "ASN_BASIC_INTEGER", "ASN_BASIC_OBJECT_IDENTIFIER" or "ASN_BASIC_BIT_STRING", "uint64" will be added in front of the expression
 *   and the identifier in lowercase after it.
 * - If the expression type is "ASN_BASIC_ENUMERATED", "uint64" will be added in front of the expression
 *   and the identifier in lowercase after it.
 * - If the expression type is "ASN_STRING_NumericString", "ASN_STRING_IA5String" or "ASN_STRING_UTF8String",
 *   "string" is added in front of the expression and the identifier in lowercase after it.
 * - If the expression type is "ASN_BASIC_OCTET_STRING", "uint64[]" will be added in front of the expression,
 *   because it is an array and the identifier in lowercase after it.
 * - If the expression type is "ASN_BASIC_BOOLEAN", "bool" will be added in front of the expression,
 *   because it is an array and the identifier in lowercase is added after it.
 * - If the expression type is "ASN_CONSTR_SEQUENCE", the static variable "identifierForSequenceRegion" gets its value by the current identifier, but only if the identifier is
 *   equals "regional". The current datatype will be set to "sequence".
 * - If the expression type is "ASN_CONSTR_SEQUENCE_OF" it'll be formatted with the method call "toFormattedSequenceOf(...)".
 *   But if the current identifier is "regional" there will be a different handling with the marker flag "EM_OPTIONAL".
 * - If the expression type is "ASN_CONSTR_CHOICE", a specific text will be added at the beginning.
 *   After that the data types with the identifiers will be added in the correct format.
 *   A bool variable for checking if the current expression is type choice, will be set to true.
 * - If non of the expression types mention above are the case, it will be checked, if the bool variable for choice is set to false or true.
 *   If the bool variable is set false, it'll be checked if the reference is equals "REG-EXT-ID-AND-TYPE".
 *   If this is the case, a specific output format will be added to the summary text char array.
 *   If the bool variable is true and the reference is set, this means the expression is type choice.
 *   A special container text will be added to the container text char array. This text will be added at the end of the expression.
 * If the level is higher than 1 and the identifier and the reference have been set:
 * - A specific format of the reference will be added to the summary text char array.
 * If the level is higher than 1 and the identifier has been set but not the reference, it will be checked if the static variable
 *   to mark the end of a sequence is false. If this is the case. A formatted output will be added to the summary text char array.
 *   Otherwise, a different formatted output will be added.
 * If the level is 0, the summary text char array will be written into a file and set empty.
 * @param asn
 * @param mod
 * @param tc
 * @param flags
 * @param level
 * @return
 */
static int asn1write_expr(asn1p_t *asn, asn1p_module_t *mod, asn1p_expr_t *tc, enum asn1write_flags flags, int level);

/**
 * Added that the expressions are concatenated to the summary text char array.
 * @param asn
 * @param mod
 * @param tc
 * @param flags
 * @param level
 * @return
 */
static int asn1write_expr_dtd(asn1p_t *asn, asn1p_module_t *mod, asn1p_expr_t *tc, enum asn1write_flags flags, int level);

/**
 * In this function the number of words and the index, at which the last word starts, are being calculated.
 * Exceptions:
 * - If the first, second and third letter are uppercase and there is no fourth letter, the number of names is set to 1.
 * - If the first, second and third letter are uppercase and there is a fourth letter, to the number of names and to the index, 3 is added.
 * - If the last and the second last letter are uppercase, 1 will be added to the number of names.
 * - If the first letter is lowercase, 1 is subtracted from the calculated index.
 * - If the number of names is three and the last and second last letter is uppercase, 1 and the calculated sum is added to the index.
 * @param identifier
 * @return
 */
static struct counter * toSplitIdentifier(char * identifier);

/**
 * A char array will be formatted to the ROS specific format.
 * Special handling if the bool variable for the choice is set true.
 * @param identifierChar
 * @param toUpper The char array will be converted to uppercase if true, else lowercase.
 * @param toPrint If true the char array will be added to the summary text char array, else it'll be set as value to a static variable.
 */
static void toFormatString(char * identifierChar, bool toUpper, bool toPrint);

/**
 * A char array will be formatted to the lowercase ROS-specific format for the optional field.
 * @param identifierChar
 * @return
 */
static char* toFormatAndLowerIdentifierForOptionalField(char * identifierChar);

/**
 * An expression will be formatted to the lowercase ROS-specific format on the basis of the previous calculated index and number of words.
 * It will be added to the summary text char array.
 * @param tc
 * @param flags
 * @param regionalCheck
 */
static void toFormatAndLowerString(char * identifierString, enum asn1write_flags flags, bool regionalCheck);

/**
* A char array will be formatted to the lowercase ROS-specific format for the regional field.
 * @param identifierChar
 */
static void toFormatIdentifierForRegion(char * identifierChar);

/**
 * The identifier will be converted to uppercase.
 * @param identifier
 * @return
 */
static char* toUpperIdentifier(char * identifier);

/**
 * The identifier will be formatted to the ROS-specific format and converted to uppercase.
 * It will be added to the summary text char array.
 * @param identifierChar
 */
static void toUpperIdentifierForEverythingText(char* identifierChar);

/**
 * The identifier will be converted to lowercase.
 * @param identifierChar
 * @return
 */
static char* toLowerIdentifier(char * identifierChar);

/**
 * Based on the previous calculated index and number of words, the ROS-specific format for the expressions will be added to the summary text char array.
 * Exception: If the current expression is type "regional", "Reg" will be added in front.
 * @param tc
 * @param flags
 * @param regionalCheck
 */
static void toFormattedSequenceOf(asn1p_expr_t *tc, enum asn1write_flags flags, bool regionalCheck, int level);

/**
 * It will be checked if the identifier contains only uppercase letters.
 * @param identifier
 * @return If the identifier only contains uppercase letters, true will be returned.
 */
static bool checkIfEverythingIsUpperCaseInIdentifier(char * identifier);

/**
 * If the character '-' occurs in the char array, it will be skipped from adding to the summary text char array.
 * The char array will be added afterwards.
 * @param stringTypeOne
 */
static void toUpperIdentifierForSequenceOf(char * stringTypeOne);

static int asn1write_with_syntax(const asn1p_wsyntx_t *wx, enum asn1write_flags flags);

#endif  // ASN_1_C_FORK_ASN1ROSPARSER_H
