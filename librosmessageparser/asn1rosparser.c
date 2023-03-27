//
// Created by Patrizia Neubauer on 11.08.22.
//

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <asn1_buffer.h>
#include <asn1_namespace.h>
#include <asn1parser.h>
#include <asn1fix_export.h>
#include <ctype.h>
#include <stdbool.h>
#include <malloc.h>
#include <time.h>

#include "asn1rosparser.h"

typedef enum {
    PRINT_STDOUT,
    GLOBAL_BUFFER,
} print_method_e;
static print_method_e print_method_;

/* Pedantically check fwrite's return value. */
static size_t safe_fwrite(const void *ptr, size_t size) {
    size_t ret;

    switch(print_method_) {
    case PRINT_STDOUT:
        ret = fwrite(ptr, 1, size, stdout);
        break;
    case GLOBAL_BUFFER:
        abuf_add_bytes(&all_output_, ptr, size);
        ret = size;
        break;
    }

    return ret;
}

/*
 * Writes the contents of the parsed ASN tree.
 */
int asn1write(asn1p_t *asn, enum asn1write_flags flags, char * path) {

    asn1p_module_t *mod;
    int modno = 0;
    strcpy(dirPath, path);

    if(asn == NULL) {
        errno = EINVAL;
        return -1;
    }

    TQ_FOR(mod, &(asn->modules), mod_next) {
        if(mod->_tags & MT_STANDARD_MODULE)
            return 0; /* Ignore modules imported from skeletons */
        asn1write_module(asn, mod, flags);
    }

    return 0;
}

static int asn1write_ref(const asn1p_ref_t *ref, enum asn1write_flags flags, int level) {
    (void)flags; /* Unused argument */

    char help[150];
    int i = 0;
    for(size_t cc = 0; cc < ref->comp_count; cc++) {
        for(size_t dd = 0; dd < strlen(ref->components[cc].name); dd++) {
            if(ref->components[cc].name[dd] != '-') {
                help[i] = ref->components[cc].name[dd]; i++;
            }
        }
        help[i] = '\0';
        strcat(everythingText, help);
        strcpy(help, "");
    }

    return 0;
}

static int asn1write_ref_container(const asn1p_ref_t *ref, enum asn1write_flags flags, int level) {
    (void)flags; /* Unused argument */

    char ident [150];
    int j = 0;

    for(int i = 0; i < strlen(ref->components[0].name) + 1; i++) {
        if(ref->components[0].name[i] == '-') {
            i++;
            ident[j] = toupper(ref->components[0].name[i]); j++; i++;
        }

        ident[j] = ref->components[0].name[i]; j++;
    }

    if(islower(ident[0])) ident[0] = toupper(ident[0]);

    strcat(containerText, ident);

    return 0;
}

static int asn1write_ref_toUpperForEverythingText(const asn1p_ref_t *ref, enum asn1write_flags flags, int level) {
    (void)flags; /* Unused argument */

    char toCharArrayOne[2];
    char toCharArrayTwo[4];
    char helpAllIdentifier[10000];
    strcpy(helpAllIdentifier, "");

    for(size_t cc = 0; cc < ref->comp_count; cc++) {
        if(ref->components[cc].name != '.') {
            for(int i = 0; i < strlen(ref->components[cc].name) + 1; i++) {
                if(ref->components[cc].name[i] == '-' || ref->components[cc].name[i] == '_') {
                    strcat(helpAllIdentifier, "_");
                } else if(ref->components[cc].name[i+1] != NULL && islower(ref->components[cc].name[i]) && isupper(ref->components[cc].name[i+1])) {
                    toCharArrayTwo[0] = ref->components[cc].name[i];
                    toCharArrayTwo[1] = '_';
                    toCharArrayTwo[2] = ref->components[cc].name[i+1]; i++;
                    toCharArrayTwo[3] = '\0';
                    strcat(helpAllIdentifier, toCharArrayTwo);
                } else {
                    toCharArrayOne[0] = ref->components[cc].name[i];
                    toCharArrayOne[1] = '\0';
                    strcat(helpAllIdentifier, toCharArrayOne);
                }
            }
        }
    }

    strcat(everythingText, toUpperIdentifier(helpAllIdentifier));

    return 0;
}

static int asn1write_ref_toUpperWithFormat(const asn1p_ref_t *ref, enum asn1write_flags flags, int level) {
    (void)flags; /* Unused argument */
    char charHelp[1000];
    strcpy(charHelp, "");

    for(size_t cc = 0; cc < ref->comp_count; cc++) {
        strcat(charHelp, ref->components[cc].name);
    }

    toFormatString(charHelp, true, true);

    return 0;
}

static int asn1write_params(const asn1p_paramlist_t *pl, enum asn1write_flags flags) {
    if(pl) {
        int i;
        for(i = 0; i < pl->params_count; i++) {
            if(pl->params[i].governor) {
                asn1write_ref(pl->params[i].governor, flags, 0);
            }
            strcat(everythingText, pl->params[i].argument);
        }
    }

    return 0;
}

static int asn1write_with_syntax(const asn1p_wsyntx_t *wx, enum asn1write_flags flags) {
    if(wx) {
        const asn1p_wsyntx_chunk_t *wc;
        TQ_FOR(wc, &(wx->chunks), next) {
            switch(wc->type) {
            case WC_LITERAL:
            case WC_WHITESPACE:
            case WC_FIELD:
                strcat(everythingText, wc->content.token);
                break;
            case WC_OPTIONALGROUP:
                strcat(everythingText, "[");
                asn1write_with_syntax(wc->content.syntax,flags);
                strcat(everythingText, "]");
                break;
            }
        }
    }

    return 0;
}

const char * asn1p_constraint_string(const asn1p_constraint_t *ct) {
    size_t old_len = all_output_.length;
    print_method_e old_method = print_method_;
    print_method_ = GLOBAL_BUFFER;
    asn1write_constraint(NULL, ct, APF_WRITE_ROS_MESSAGE);
    print_method_ = old_method;
    return &all_output_.buffer[old_len];
}

static int asn1write_module(asn1p_t *asn, asn1p_module_t *mod,
                 enum asn1write_flags flags) {
    asn1p_expr_t *tc;

    TQ_FOR(tc, &(mod->members), next) {
        asn1write_expr(asn, mod, tc, flags, 0);
    }

    return 0;
}

static int asn1write_constraint(char *asn1p_expr_s, const asn1p_constraint_t *ct, enum asn1write_flags flags) {
    int symno = 0;
    int perhaps_subconstraints = 0;

    if(ct == 0) return 0;

    if(!choiceCheck) {
        /*char helpas [2000];
        int a = ct->type;
        sprintf(helpas, " %d ", a);
        strcat(everythingText, helpas);*/
        switch(ct->type) {
        case ACT_EL_TYPE:
            asn1write_value(ct->containedSubtype, flags);
            perhaps_subconstraints = 1;
            break;
        case ACT_EL_VALUE:
            if(strcmp(dataTypeHelp, "octetstring") == 0) {
                strcat(everythingText, "1..");
            } else if(isBitString) {
                strcat(everythingText, " = ");
            }

            asn1write_value(ct->value, flags);
            perhaps_subconstraints = 1;
            break;
        case ACT_EL_RANGE:
            if(isBitString) strcat(everythingText, "\n");
        case ACT_EL_LLRANGE:
        case ACT_EL_RLRANGE:
        case ACT_EL_ULRANGE:
            if(check && strcmp(dataTypeHelp, "octetstring") == 0  && !choiceCheck) {
                asn1write_value(ct->range_start, flags);
                switch(ct->type) {
                case ACT_EL_RANGE:
                    strcat(everythingText, "..");
                    break;
                default:
                    break;
                }
                asn1write_value(ct->range_stop, flags);
                break;
            } else if(check && strcmp(dataTypeHelp, "sequenceof") == 0 && !choiceCheck) {
                asn1write_value(ct->range_start, flags);
                switch(ct->type) {
                case ACT_EL_RANGE:
                    strcat(followingTextSequenceOf, "..");
                    break;
                default:
                    break;
                }
                asn1write_value(ct->range_stop, flags);
                break;
            } else  {
                strcat(everythingText, dataTypeHelp);
                strcat(everythingText, " ");
                toFormatString(tcHelp->Identifier, true, true);
                strcat(everythingText, "_RANGE_MIN = ");
                asn1write_value(ct->range_start, flags);
                strcat(everythingText, "\n");

                switch(ct->type) {
                case ACT_EL_RANGE:
                    strcat(everythingText, dataTypeHelp);
                    strcat(everythingText, " ");
                    toFormatString(tcHelp->Identifier, true, true);
                    strcat(everythingText, "_RANGE_MAX = ");
                    asn1write_value(ct->range_stop, flags);
                    strcat(everythingText, "\n");
                    break;
                default:
                    break;
                }
                break;
            }
        case ACT_EL_EXT: break;
        case ACT_CT_SIZE:
            asn1write_constraint(asn1p_expr_s, ct->elements[0], flags);
        case ACT_CT_FROM:
            switch(ct->type) {
            case ACT_CT_SIZE:
                if(strcmp(dataTypeHelp, "octetstring") == 0) {
                    strcat(everythingText, "#size(");
                    asn1write_constraint(asn1p_expr_s, ct->elements[0], flags);
                    strcat(everythingText, ")\n");
                } else if(strcmp(dataTypeHelp, "sequenceof") == 0) {
                    strcat(followingTextSequenceOf, "#size(");
                    asn1write_constraint(asn1p_expr_s, ct->elements[0], flags);
                    strcat(followingTextSequenceOf, ")\n");
                }
                break;
            default:
                break;
            }
            break;
        case ACT_CT_WCOMP:
            perhaps_subconstraints = 1;
            break;
        case ACT_CT_WCOMPS: {
        } break;
        case ACT_CT_CTDBY:
            safe_fwrite(ct->value->value.string.buf, ct->value->value.string.size);
            break;
        case ACT_CT_CTNG:
            asn1write_expr(ct->value->value.v_type->module->asn1p,
                           ct->value->value.v_type->module, ct->value->value.v_type,
                           flags, 1);
            break;
        case ACT_CT_PATTERN:
            asn1write_value(ct->value, flags);
            break;
        case ACT_CA_SET:
            symno++; /* Fall through */
        case ACT_CA_CRC:
            symno++; /* Fall through */
        case ACT_CA_CSV:
            symno++; /* Fall through */
        case ACT_CA_UNI:
            symno++; /* Fall through */
        case ACT_CA_INT:
            symno++; /* Fall through */
        case ACT_CA_EXC: {
            char *symtable[] = {" EXCEPT ", " ^ ", " | ", ",", "", "("};
            unsigned int i;

            for(i = 0; i < ct->el_count; i++) {
                if(asn1p_expr_s != NULL) asn1write_constraint(asn1p_expr_s, ct->elements[i], flags);
            }
        } break;
        case ACT_CA_AEX:
            perhaps_subconstraints = 1;
            break;
        case ACT_INVALID:
            break;
        }

        if(perhaps_subconstraints && ct->el_count) {
            asn1write_constraint(asn1p_expr_s, ct->elements[0], flags);
        }
    }

    return 0;
}

static int asn1write_value(const asn1p_value_t *val, enum asn1write_flags flags) {
    char help[100];

    if(val == NULL) return 0;

    switch(val->type) {
    case ATV_NOVALUE:
        return 0;
    case ATV_NULL:
        if(!choiceCheck) strcat(everythingText, "NULL");
        else strcat(containerText, "NULL");
        return 0;
    case ATV_REAL:
        return 0;
    case ATV_TYPE:
        asn1write_expr(val->value.v_type->module->asn1p, val->value.v_type->module, val->value.v_type, flags, 0);
        return 0;
    case ATV_INTEGER:
        if(isSequenceOf) {
            strcat(followingTextSequenceOf, asn1p_itoa(val->value.v_integer));
        } else strcat(everythingText, asn1p_itoa(val->value.v_integer));

        return 0;
    case ATV_UNPARSED:
        strcpy(help, (char *)val->value.string.buf);
        char delimiter[] = "{} \t";
        char *ptr;
        ptr = strtok(help, delimiter);
        toFormatIdentifierForRegion(ptr);
        strcat(everythingText, identifierForSequenceRegion);
        strcat(everythingText, " reg_ext_value");

        return 0;
    case ATV_REFERENCED:
        return asn1write_ref(val->value.reference, flags, 0);
    case ATV_VALUESET:
        return asn1write_constraint(NULL, val->value.constraint, flags);
    case ATV_CHOICE_IDENTIFIER:
        strcat(everythingText, val->value.choice_identifier.identifier);
        return asn1write_value(val->value.choice_identifier.value, flags);
    case ATV_MAX:
        strcat(everythingText, "MAX");
        return 0;
    case ATV_MIN:
        strcat(everythingText, "MIN");
        return 0;
    }

    return 0;
}

static int asn1write_expr(asn1p_t *asn, asn1p_module_t *mod, asn1p_expr_t *tc, enum asn1write_flags flags, int level) {
    int SEQ_OF = 0;
    int has_space = 0;
    char counterCharEnumerated[100];

    char* p = ASN_EXPR_TYPE2STR(tc->expr_type);
    FILE *fp;

    if(level == 0) {
        if(tc->Identifier) strcpy(identifierForRegChoice, tc->Identifier);
        if(tc->Identifier) strcpy(identifierForSequenceRegion, tc->Identifier);
    }

    if(tc->reference && isSequenceOf)  {
        if(strcmp(tc->reference->components[0].name, "RegionalExtension") != 0) asn1write_ref(tc->reference, flags, level);
        strcat(everythingText, followingTextSequenceOf);
        isSequenceOf = false;
        strcpy(followingTextSequenceOf, "");
    }

    if((tc->Identifier &&  (!(tc->meta_type == AMT_VALUE && tc->expr_type == A1TC_REFERENCE) && (level == 0 || level == 1)))) {
        if(tc->expr_type == A1TC_UNIVERVAL && strcmp(dataTypeHelp, "bool") == 0) {
            strcat(everythingText, "bool ");
            strcat(everythingText, toUpperIdentifier(identifierHelp));
            strcat(everythingText, "_");
            toFormatString(tc->Identifier, true, true);
            strcat(everythingText, " = ");

            if(tc->value) {
                asn1write_value(tc->value, flags);
            }

            strcat(everythingText, "\n");
            isBitString = false;
        } else if(tc->expr_type == A1TC_UNIVERVAL && strcmp(dataTypeHelp, "string") == 0) {
            strcat(everythingText, "string ");
            strcat(everythingText, toUpperIdentifier(identifierHelp));
            strcat(everythingText, "_");
            toFormatString(tc->Identifier, true, true);
            strcat(everythingText, " = ");

            if(tc->value) {
                asn1write_value(tc->value, flags);
            }

            strcat(everythingText, "\n");
            isBitString = false;
        } else if(tc->expr_type == A1TC_UNIVERVAL && strcmp(dataTypeHelp, "enumerated") == 0) {
            if(tc->Identifier) {
                strcat(everythingText, "int64 ");
                strcat(everythingText, toUpperIdentifier(identifierHelp));
                strcat(everythingText, "_");
                toFormatString(tc->Identifier, true, true);
                strcat(everythingText, " = ");

                if(tc->value) {
                    asn1write_value(tc->value, flags);
                } else {
                    sprintf(counterCharEnumerated, "%d", counterEnumerated);
                    strcat(everythingText, counterCharEnumerated);
                    counterEnumerated++;
                }

                strcat(everythingText, "\n");
            }
            isBitString = false;
        } else if(tc->expr_type == A1TC_UNIVERVAL && strcmp(dataTypeHelp, "int64") == 0) {
            if(isBitString) strcat(everythingText, "# int64 ");
            else strcat(everythingText, "int64 ");
            strcat(everythingText, toUpperIdentifier(identifierHelp));
            strcat(everythingText, "_");
            toFormatString(tc->Identifier, true, true);
            strcat(everythingText, " = ");

            if(tc->value) {
                asn1write_value(tc->value, flags);
            } else {
                asn1write_value(0, flags);
            }

            strcat(everythingText, "\n");
        } else if(tc->expr_type == ASN_BASIC_INTEGER || tc->expr_type == ASN_BASIC_OBJECT_IDENTIFIER) {
            if(!choiceCheck) toFormatString(tc->Identifier, false, false);
            strcpy(dataTypeHelp, "int64");
            check = true;

            if(!choiceCheck) {
                if(((tc->marker.flags & EM_OPTIONAL) != EM_OPTIONAL) && level >= 1) strcat(everythingText, "\n");
                if((tc->marker.flags & EM_OPTIONAL) == EM_OPTIONAL) {
                    if(level > 0) strcat(everythingText, "\n");
                    strcat(everythingText, "# Optional Field\nbool ");
                    strcat(everythingText, toFormatAndLowerIdentifierForOptionalField(tc->Identifier));
                    strcat(everythingText, "_present 0");
                    strcat(everythingText, "\n");
                }

                strcat(everythingText, dataTypeHelp);
                strcat(everythingText, " ");
                toFormatString(tc->Identifier, false, true);
                strcat(everythingText, "\n");
                tcHelp = tc;
                asn1write_constraint(tc->Identifier, tc->constraints, flags);
            } else {
                char number[20];
                sprintf(number, "%d", containerCount);
                strcat(everythingText, "int64 ");
                strcat(everythingText, identifierForContainer);
                strcat(everythingText, "_");
                choiceCheck = false;
                toUpperIdentifierForEverythingText(tc->Identifier);
                choiceCheck = true;
                strcat(everythingText, " = ");
                strcat(everythingText, number);
                strcat(everythingText, "\n");
                containerCount++;
                sprintf(number, "%d", containerCount-1);
                strcat(containerText, "\n# container ");
                strcat(containerText, number);
                strcat(containerText, "\n");

                strcat(containerText, "int64 ");
                toFormatString(tc->Identifier, false, false);
                strcat(containerText, "\n");
            }
            isBitString = false;
        } else if(tc->expr_type == ASN_BASIC_BIT_STRING) {
            isBitString = true;
            if(!choiceCheck) toFormatString(tc->Identifier, false, false);
            strcpy(dataTypeHelp, "int64");
            check = true;

            if(!choiceCheck) {
                if(((tc->marker.flags & EM_OPTIONAL) != EM_OPTIONAL) && level >= 1) strcat(everythingText, "\n");
                if((tc->marker.flags & EM_OPTIONAL) == EM_OPTIONAL) {
                    if(level > 0) strcat(everythingText, "\n");
                    strcat(everythingText, "# Optional Field\nbool ");
                    strcat(everythingText, toFormatAndLowerIdentifierForOptionalField(tc->Identifier));
                    strcat(everythingText, "_present 0");
                    strcat(everythingText, "\n");
                }

                tcHelp = tc;
                strcat(everythingText, "uint8[] ");
                toFormatString(tc->Identifier, false, true);
                strcat(everythingText, "_buf\n");

                strcat(everythingText, "int64 ");
                toFormatString(tc->Identifier, false, true);
                strcat(everythingText, "_bits_unused\n");

                strcat(everythingText, "int64 ");
                toFormatString(tc->Identifier, true, true);
                strcat(everythingText, "_SIZE");

                asn1write_constraint(tc->Identifier, tc->constraints, flags);
                strcat(everythingText, "\n");
            } else {
                char number[20];
                sprintf(number, "%d", containerCount);
                strcat(everythingText, "int64 ");
                strcat(everythingText, identifierForContainer);
                strcat(everythingText, "_");
                choiceCheck = false;
                toUpperIdentifierForEverythingText(tc->Identifier);
                choiceCheck = true;
                strcat(everythingText, " = ");
                strcat(everythingText, number);
                strcat(everythingText, "\n");
                containerCount++;
                sprintf(number, "%d", containerCount-1);
                strcat(containerText, "\n# container ");
                strcat(containerText, number);
                strcat(containerText, "\n");

                strcat(containerText, "int64 ");
                toFormatString(tc->Identifier, false, false);
                strcat(containerText, "\n");
            }
        } else if(tc->expr_type == ASN_BASIC_ENUMERATED) {
            if(!choiceCheck) toFormatString(tc->Identifier, false, false);
            strcpy(dataTypeHelp, "enumerated");
            check = true;
            if(!choiceCheck) {
                if(((tc->marker.flags & EM_OPTIONAL) != EM_OPTIONAL)
                   && level >= 1)
                    strcat(everythingText, "\n");
                if((tc->marker.flags & EM_OPTIONAL) == EM_OPTIONAL) {
                    if(level > 0) strcat(everythingText, "\n");
                    strcat(everythingText, "# Optional Field\nbool ");
                    strcat(everythingText,
                           toFormatAndLowerIdentifierForOptionalField(
                               tc->Identifier));
                    strcat(everythingText, "_present 0");
                    strcat(everythingText, "\n");
                }

                strcat(everythingText, "int64 ");
                toFormatString(tc->Identifier, false, true);
                strcat(everythingText, "\n");
            } else {
                char number[20];
                sprintf(number, "%d", containerCount);
                strcat(everythingText, "int64 ");
                strcat(everythingText, identifierForContainer);
                strcat(everythingText, "_");
                choiceCheck = false;
                toUpperIdentifierForEverythingText(tc->Identifier);
                choiceCheck = true;
                strcat(everythingText, " = ");
                strcat(everythingText, number);
                strcat(everythingText, "\n");
                containerCount++;
                sprintf(number, "%d", containerCount-1);
                strcat(containerText, "\n# container ");
                strcat(containerText, number);
                strcat(containerText, "\n");

                strcat(containerText, "int64 ");
                toFormatString(tc->Identifier, false, false);
                strcat(containerText, "\n");
            }
            isBitString = false;
        } else if(tc->expr_type == ASN_STRING_NumericString
                  || tc->expr_type == ASN_STRING_IA5String
                  || tc->expr_type == ASN_STRING_UTF8String
                  || tc->expr_type == ASN_STRING_UniversalString) {
            toFormatString(tc->Identifier, false, false);
            strcpy(dataTypeHelp, "string");
            check = true;
            if(((tc->marker.flags & EM_OPTIONAL) != EM_OPTIONAL) && level >= 1) strcat(everythingText, "\n");
            if((tc->marker.flags & EM_OPTIONAL) == EM_OPTIONAL) {
                if(level > 0) strcat(everythingText, "\n");
                strcat(everythingText, "# Optional Field\nbool ");
                strcat(everythingText, toFormatAndLowerIdentifierForOptionalField(tc->Identifier));
                strcat(everythingText, "_present 0");
                strcat(everythingText, "\n");
            }

            strcat(everythingText, dataTypeHelp);
            strcat(everythingText, " ");
            toFormatString(tc->Identifier, false, true);
            strcat(everythingText, "\n");
            tcHelp = tc;
            asn1write_constraint(tc->Identifier, tc->constraints, flags);
            isBitString = false;
        } else if(tc->expr_type == ASN_BASIC_OCTET_STRING) {
            if(!choiceCheck) toFormatString(tc->Identifier, false, false);
            strcpy(dataTypeHelp, "octetstring");
            check = true;

            if(!choiceCheck) {
                if(((tc->marker.flags & EM_OPTIONAL) != EM_OPTIONAL) && level >= 1) strcat(everythingText, "\n");
                if((tc->marker.flags & EM_OPTIONAL) == EM_OPTIONAL) {
                    if(level > 0) strcat(everythingText, "\n");
                    strcat(everythingText, "# Optional Field\nbool ");
                    strcat(everythingText, toFormatAndLowerIdentifierForOptionalField(tc->Identifier));
                    strcat(everythingText, "_present 0");
                    strcat(everythingText, "\n");
                }

                strcat(everythingText, "int64[] ");
                toFormatString(tc->Identifier, false, true);
                strcat(everythingText, " ");
                asn1write_constraint(tc->Identifier, tc->constraints, flags);
                strcat(everythingText, "\n");
            } else {
                char number[20];
                sprintf(number, "%d", containerCount);
                strcat(everythingText, "int64 ");
                strcat(everythingText, identifierForContainer);
                strcat(everythingText, "_");
                choiceCheck = false;
                toUpperIdentifierForEverythingText(tc->Identifier);
                choiceCheck = true;
                strcat(everythingText, " = ");
                strcat(everythingText, number);
                strcat(everythingText, "\n");
                containerCount++;
                sprintf(number, "%d", containerCount-1);
                strcat(containerText, "\n# container ");
                strcat(containerText, number);
                strcat(containerText, "\n");

                strcat(containerText, "int64[] ");
                toFormatString(tc->Identifier, false, false);
                strcat(containerText, "\n");
            }
            isBitString = false;
        } else if(tc->expr_type == ASN_BASIC_BOOLEAN) {
            if(!choiceCheck) toFormatString(tc->Identifier, false, false);
            strcpy(dataTypeHelp, "bool");
            check = true;
            if(((tc->marker.flags & EM_OPTIONAL) != EM_OPTIONAL) && level >= 1) strcat(everythingText, "\n");
            if((tc->marker.flags & EM_OPTIONAL) == EM_OPTIONAL) {
                if(level > 0) strcat(everythingText, "\n");
                strcat(everythingText, "# Optional Field\nbool ");
                strcat(everythingText, toFormatAndLowerIdentifierForOptionalField(tc->Identifier));
                strcat(everythingText, "_present 0");
                strcat(everythingText, "\n");
            }

            strcat(everythingText, dataTypeHelp);
            strcat(everythingText, " ");
            toFormatString(tc->Identifier, false, true);
            strcat(everythingText, "\n");
            tcHelp = tc;
            asn1write_constraint(tc->Identifier, tc->constraints, flags);
            isBitString = false;
        } else if(tc->expr_type == ASN_CONSTR_SEQUENCE) {
            if(!choiceCheck) toFormatString(tc->Identifier, false, false);
            strcpy(dataTypeHelp, "sequence");
            tcHelp = tc;
            sequenceEnd = false;

            if(strcmp(tc->Identifier, "regional") == 0) {
                strcpy(identifierForSequenceRegion, tc->Identifier);
                identifierForSequenceRegion[strlen(identifierForSequenceRegion)] = '\0';
            }
            isBitString = false;
        } else if(tc->expr_type == ASN_CONSTR_SEQUENCE_OF) {
            SEQ_OF = 1;
            isSequenceOf = true;

            if(!choiceCheck) toFormatString(tc->Identifier, false, false);
            strcpy(dataTypeHelp, "sequenceof");

            if(strcmp(tc->Identifier, "regional") == 0) {
                if(((tc->marker.flags & EM_OPTIONAL) != EM_OPTIONAL) && level >= 1) strcat(everythingText, "\n");
                if((tc->marker.flags & EM_OPTIONAL) == EM_OPTIONAL) {
                    if(level > 0) strcat(everythingText, "\n");
                    strcat(everythingText,"# Optional Field\nbool regional_present 0\n");
                }

                strcpy(identifierHelp, identifierForSequenceRegion);

                toFormattedSequenceOf(tc, flags, true, level);
            } else {
                if(((tc->marker.flags & EM_OPTIONAL) != EM_OPTIONAL)
                   && level >= 1)
                    strcat(everythingText, "\n");
                if((tc->marker.flags & EM_OPTIONAL) == EM_OPTIONAL) {
                    if(level > 0) strcat(everythingText, "\n");
                    strcat(everythingText, "# Optional Field\nbool ");
                    strcat(everythingText,
                           toFormatAndLowerIdentifierForOptionalField(
                               identifierForSequenceRegion));
                    strcat(everythingText, "_present 0");
                    strcat(everythingText, "\n");
                }
                if(((tc->marker.flags & EM_OPTIONAL) != EM_OPTIONAL)
                   && level >= 1)
                    strcat(everythingText, "\n");

                toFormattedSequenceOf(tc, flags, false, level);
            }
            asn1write_constraint(tc->Identifier, tc->constraints, flags);
            check = true;
            isBitString = false;
        } else if (tc->expr_type == ASN_CONSTR_CHOICE) {
            if(!choiceCheck) toFormatString(tc->Identifier, false, false);

            if(level > 0) strcat(everythingText, "\n");
            if((tc->marker.flags & EM_OPTIONAL) == EM_OPTIONAL) {
                if(level > 0) strcat(everythingText, "\n");
                strcat(everythingText, "# Optional Field\nbool ");
                strcat(everythingText, toFormatAndLowerIdentifierForOptionalField(identifierForSequenceRegion));
                strcat(everythingText, "_present 0");
                strcat(everythingText, "\n");
            }

            strcat(everythingText, "# CHOICE! - Choose exactly of the containers\nint64 ");
            strcat(everythingText, toLowerIdentifier(identifierForContainer));
            strcat(everythingText, "_container_select 0\n");
            strcpy(dataTypeHelp, "int64");
            choiceCheck = true;
            choiceEnd = false;
            strcat(everythingText, "int64 ");
            strcat(everythingText, identifierForContainer);
            strcat(everythingText, "_NOTHING = 0\n");
            containerCount++;
            isBitString = false;
        } else {
            if(!choiceCheck) {
                toFormatString(tc->Identifier, false, false);
                if(tc->reference) {
                    if(((tc->marker.flags & EM_OPTIONAL) != EM_OPTIONAL) && level >= 1)  strcat(everythingText, "\n");
                    if((tc->marker.flags & EM_OPTIONAL) == EM_OPTIONAL) {
                        if(level > 0) strcat(everythingText, "\n");
                        strcat(everythingText, "# Optional Field\nbool ");
                        strcat(everythingText, toFormatAndLowerIdentifierForOptionalField(tc->Identifier));
                        strcat(everythingText, "_present 0\n");
                    }

                    if (strcmp(tc->reference->components[0].name, "REG-EXT-ID-AND-TYPE") == 0) {
                        toFormatIdentifierForRegion(tc->Identifier);
                        strcat(everythingText, "RegionId region_id\n");
                    } else {
                        asn1write_ref(tc->reference, flags, level);
                        strcat(everythingText, " ");
                        toFormatString(tc->Identifier, false, true);
                    }
                    strcat(everythingText, "\n");
                }
                tcHelp = tc;
                asn1write_constraint(tc->Identifier, tc->constraints, flags);
            } else {
                if(tc->reference) {
                    char number[20];
                    sprintf(number, "%d", containerCount);
                    strcat(everythingText, "int64 ");
                    strcat(everythingText, identifierForContainer);
                    strcat(everythingText, "_");
                    choiceCheck = false;
                    toUpperIdentifierForEverythingText(tc->Identifier);
                    choiceCheck = true;
                    strcat(everythingText, " = ");
                    strcat(everythingText, number);
                    strcat(everythingText, "\n");
                    asn1write_constraint(tc->Identifier, tc->constraints, flags);
                    containerCount++;
                    sprintf(number, "%d", containerCount-1);
                    strcat(containerText, "\n# container ");
                    strcat(containerText, number);
                    strcat(containerText, "\n");

                    if(strcmp(tc->reference->components[0].name, "RegionalExtension") == 0) {
                        strcat(containerText, "Reg");
                        strcat(containerText, identifierForRegChoice);
                    } else {
                        asn1write_ref_container(tc->reference, flags, level);
                    }
                    strcat(containerText, " ");
                    toFormatString(tc->Identifier, false, false);
                    strcat(containerText, "\n");
                }
            }
            isBitString = false;
        }
    } else if(tc->Identifier && tc->Identifier[0] != '.') {
        /* Wenn z.B. in einer Sequence für ein Attribut eine Liste von weiteren Attributen vorhanden ist. */
        if(tc->reference) {
            if(choiceCheck) {
                char number[20];
                sprintf(number, "%d", containerCount);
                strcat(everythingText, "int64 ");
                strcat(everythingText, identifierForContainer);
                strcat(everythingText, "_");
                asn1write_ref_toUpperForEverythingText(tc->reference, flags, level);
                strcat(everythingText, " = ");
                strcat(everythingText, number);
                strcat(everythingText, "\n");
                containerCount++;
                sprintf(number, "%d", containerCount-1);
                strcat(containerText, "\n# container ");
                strcat(containerText, number);
                strcat(containerText, "\n");
                asn1write_ref_container(tc->reference, flags, level);
                strcat(containerText, " ");
                toFormatString(tc->Identifier, false, false);
                strcat(containerText, "\n");
            } else {
                if((tc->marker.flags & EM_OPTIONAL) == EM_OPTIONAL) {
                    if(level > 0) strcat(everythingText, "\n");
                    strcat(everythingText, "# Optional Field\nbool ");
                    strcat(everythingText, toFormatAndLowerIdentifierForOptionalField(tc->Identifier));
                    strcat(everythingText, "_present 0");
                    strcat(everythingText, "\n");
                }

                if(!sequenceEnd) {
                    asn1write_ref(tc->reference, flags, level);
                    strcat(everythingText, " ");
                    toFormatString(tc->Identifier, false, true);
                } else {
                    if(strcmp(dataTypeHelp, "sequence") == 0) {
                        strcat(everythingText, "\n");
                        asn1write_ref(tc->reference, flags, level);
                        strcat(everythingText, " ");
                        toFormatString(tc->Identifier, false, true);
                    } else {
                        if(!choiceCheck) {
                            strcat(everythingText, dataTypeHelp);
                            strcat(everythingText, " ");
                            asn1write_ref_toUpperWithFormat(tc->reference, flags, level);
                            strcat(everythingText, "_");
                            toFormatString(tc->Identifier, true, true);
                            strcat(everythingText, " = ");

                            if(tc->value) {
                                asn1write_value(tc->value, flags);
                            }
                        } else {
                            char number[20];
                            sprintf(number, "%d", containerCount);
                            strcat(everythingText, "int64 ");
                            strcat(everythingText, identifierForContainer);
                            strcat(everythingText, "_");
                            choiceCheck = false;
                            toUpperIdentifierForEverythingText(tc->Identifier);
                            choiceCheck = true;
                            strcat(everythingText, " = ");
                            strcat(everythingText, number);
                            strcat(everythingText, "\n");
                            containerCount++;
                            sprintf(number, "%d", containerCount-1);
                            strcat(containerText, "\n# container ");
                            strcat(containerText, number);
                            strcat(containerText, "\n");

                            strcat(containerText, "int64 ");
                            toFormatString(tc->Identifier, false, false);
                            strcat(containerText, "\n");
                        }
                    }
                }
                strcat(everythingText, "\n");
            }
        } else if(tc->expr_type == ASN_CONSTR_CHOICE) {
            if(!choiceCheck) toFormatString(tc->Identifier, false, false);

            if(level > 0) strcat(everythingText, "\n");
            if((tc->marker.flags & EM_OPTIONAL) == EM_OPTIONAL) {
                if(level > 0) strcat(everythingText, "\n");
                strcat(everythingText, "# Optional Field\nbool ");
                strcat(everythingText, toFormatAndLowerIdentifierForOptionalField(identifierForSequenceRegion));
                strcat(everythingText, "_present 0");
                strcat(everythingText, "\n");
            }

            strcat(everythingText, "# CHOICE! - Choose exactly of the containers\nint64 ");
            strcat(everythingText, toLowerIdentifier(identifierForContainer));
            strcat(everythingText, "_container_select 0\n");
            strcpy(dataTypeHelp, "int64");
            choiceCheck = true;
            choiceEnd = false;
            strcat(everythingText, "int64 ");
            strcat(everythingText, identifierForContainer);
            strcat(everythingText, "_NOTHING = 0\n");
            containerCount++;
        } else if(tc->expr_type == ASN_BASIC_BIT_STRING) {
            isBitString = true;
            strcat(everythingText, "uint8[] ");
            toFormatString(tc->Identifier, false, true);
            strcat(everythingText, "_buf\n");

            strcat(everythingText, "int64 ");
            toFormatString(tc->Identifier, false, true);
            strcat(everythingText, "_bits_unused\n");

            strcat(everythingText, "int64 ");
            toFormatString(tc->Identifier, true, true);
            strcat(everythingText, "_SIZE");

            asn1write_constraint(tc->Identifier, tc->constraints, flags);
            strcat(everythingText, "\n");
            isBitString = false;
        } else if(strcmp(dataTypeHelp, "enumerated") == 0 && counterEnumerated > 0) {
            if(!choiceCheck) toFormatString(tc->Identifier, true, false);
            if(!choiceCheck) {
                if(tc->Identifier) {
                    strcat(everythingText, "int64 ");
                    strcat(everythingText, toUpperIdentifier(identifierHelp));
                    strcat(everythingText, "_");
                    toFormatString(tc->Identifier, true, true);
                    strcat(everythingText, " = ");

                    if(tc->value) {
                        asn1write_value(tc->value, flags);
                    } else {
                        sprintf(counterCharEnumerated, "%d", counterEnumerated);
                        strcat(everythingText, counterCharEnumerated);
                        counterEnumerated++;
                    }

                    strcat(everythingText, "\n");
                }
            } else {
                char number[20];
                sprintf(number, "%d", containerCount);
                strcat(everythingText, "int64 ");
                toFormatString(tc->Identifier, true, true);

                strcat(everythingText, "_");
                choiceCheck = false;
                toUpperIdentifierForEverythingText(tc->Identifier);
                choiceCheck = true;
                strcat(everythingText, " = ");
                strcat(everythingText, number);
                strcat(everythingText, "\n");
                containerCount++;
                sprintf(number, "%d", containerCount-1);
            }
        } else if(tc->expr_type == ASN_BASIC_OCTET_STRING) {
            if(!choiceCheck) toFormatString(tc->Identifier, false, false);
            strcpy(dataTypeHelp, "octetstring");
            check = true;

            if(!choiceCheck) {
                if(((tc->marker.flags & EM_OPTIONAL) != EM_OPTIONAL) && level >= 1) strcat(everythingText, "\n");
                if((tc->marker.flags & EM_OPTIONAL) == EM_OPTIONAL) {
                    if(level > 0) strcat(everythingText, "\n");
                    strcat(everythingText, "# Optional Field\nbool ");
                    strcat(everythingText, toFormatAndLowerIdentifierForOptionalField(tc->Identifier));
                    strcat(everythingText, "_present 0");
                    strcat(everythingText, "\n");
                }

                strcat(everythingText, "int64[] ");
                toFormatString(tc->Identifier, false, true);
                strcat(everythingText, " ");
                asn1write_constraint(tc->Identifier, tc->constraints, flags);
                strcat(everythingText, "\n");
            } else {
                char number[20];
                sprintf(number, "%d", containerCount);
                strcat(everythingText, "int64 ");
                strcat(everythingText, identifierForContainer);
                strcat(everythingText, "_");
                choiceCheck = false;
                toUpperIdentifierForEverythingText(tc->Identifier);
                choiceCheck = true;
                strcat(everythingText, " = ");
                strcat(everythingText, number);
                strcat(everythingText, "\n");
                containerCount++;
                sprintf(number, "%d", containerCount-1);
                strcat(containerText, "\n# container ");
                strcat(containerText, number);
                strcat(containerText, "\n");

                strcat(containerText, "int64 ");
                toFormatString(tc->Identifier, false, false);
                strcat(containerText, "\n");
            }
        } else if(tc->expr_type == ASN_BASIC_ENUMERATED && counterEnumerated == 0) {
            if(!choiceCheck) toFormatString(tc->Identifier, false, false);
            strcpy(dataTypeHelp, "enumerated");

            if(!choiceCheck) {
                if(((tc->marker.flags & EM_OPTIONAL) != EM_OPTIONAL) && level >= 1) strcat(everythingText, "\n");
                if((tc->marker.flags & EM_OPTIONAL) == EM_OPTIONAL) {
                    if(level > 0) strcat(everythingText, "\n");
                    strcat(everythingText, "# Optional Field\nbool ");
                    strcat(everythingText, toFormatAndLowerIdentifierForOptionalField(tc->Identifier));
                    strcat(everythingText, "_present 0");
                    strcat(everythingText, "\n");
                }

                if(tc->reference) {
                    strcat(everythingText, "\nint64 ");
                    toFormatString(tc->reference->components[0].name, false, true);
                    strcat(everythingText, "\n");
                } else {
                    strcat(everythingText, "\nint64 ");
                    toFormatString(tc->Identifier, false, true);
                    strcat(everythingText, "\n");
                }

                counterEnumerated = 1;
            } else {
                char number[20];
                sprintf(number, "%d", containerCount);
                strcat(everythingText, "int64 ");
                toFormatString(tc->Identifier, true, true);

                strcat(everythingText, "_");
                choiceCheck = false;
                toUpperIdentifierForEverythingText(tc->Identifier);
                choiceCheck = true;
                strcat(everythingText, " = ");
                strcat(everythingText, number);
                strcat(everythingText, "\n");
                containerCount++;
                sprintf(number, "%d", containerCount-1);
                strcat(containerText, "\n# container ");
                strcat(containerText, number);
                strcat(containerText, "\n");

                strcat(containerText, "int64 ");
                toFormatString(tc->Identifier, false, false);
                strcat(containerText, "\n");
            }

        } else if(counterEnumerated > 0) {
            if(!choiceCheck) {
                toFormatString(tc->Identifier, false, false);

                if(tc->Identifier) {
                    strcat(everythingText, "int64 ");
                    strcat(everythingText, toUpperIdentifier(identifierHelp));
                    strcat(everythingText, "_");
                    toFormatString(tc->Identifier, true, true);
                    strcat(everythingText, " = ");

                    if(tc->value) {
                        asn1write_value(tc->value, flags);
                    } else {
                        sprintf(counterCharEnumerated, "%d", counterEnumerated);
                        strcat(everythingText, counterCharEnumerated);
                        counterEnumerated++;
                    }

                    strcat(everythingText, "\n");
                }
            }
        } else if(!sequenceEnd && strcmp(dataTypeHelp, "enumerated") != 0 && tc->reference && tc->expr_type != ASN_CONSTR_CHOICE) {
            if(tc->value) if(tc->value->type == ATV_INTEGER) strcpy(dataTypeHelp, "int64");
            if(tc->value) if(tc->value->type == ATV_STRING || tc->value->type == ASN_STRING_UTF8String || tc->value->type == ASN_STRING_IA5String) strcpy(dataTypeHelp, "string");

            if(((tc->marker.flags & EM_OPTIONAL) != EM_OPTIONAL) && level >= 1) strcat(everythingText, "\n");
            if((tc->marker.flags & EM_OPTIONAL) == EM_OPTIONAL) {
                if(level > 0) strcat(everythingText, "\n");
                strcat(everythingText, "# Optional Field\nbool ");
                strcat(everythingText, toFormatAndLowerIdentifierForOptionalField(tc->Identifier));
                strcat(everythingText, "_present 0");
                strcat(everythingText, "\n");
            }
            strcat(everythingText, "\n");
            strcat(everythingText, dataTypeHelp);
            strcat(everythingText, " ");
            toFormatString(tc->Identifier, false, true);
            strcat(everythingText, "\n");
            asn1write_constraint(tc->Identifier, tc->constraints, flags);
        } else if(tc->expr_type == ASN_BASIC_INTEGER) {
            if(!choiceCheck) toFormatString(tc->Identifier, false, false);
            strcpy(dataTypeHelp, "int64");
            check = true;

            if(!choiceCheck) {
                if(((tc->marker.flags & EM_OPTIONAL) != EM_OPTIONAL) && level >= 1) strcat(everythingText, "\n");
                if((tc->marker.flags & EM_OPTIONAL) == EM_OPTIONAL) {
                    if(level > 0) strcat(everythingText, "\n");
                    strcat(everythingText, "# Optional Field\nbool ");
                    strcat(everythingText, toFormatAndLowerIdentifierForOptionalField(tc->Identifier));
                    strcat(everythingText, "_present 0");
                    strcat(everythingText, "\n");
                }
                strcat(everythingText, dataTypeHelp);
                strcat(everythingText, " ");
                toFormatString(tc->Identifier, false, true);
                strcat(everythingText, "\n");
                tcHelp = tc;
                asn1write_constraint(tc->Identifier, tc->constraints, flags);
            } else {
                char number[20];
                sprintf(number, "%d", containerCount);
                strcat(everythingText, "int64 ");
                strcat(everythingText, identifierForContainer);
                strcat(everythingText, "_");
                choiceCheck = false;
                toUpperIdentifierForEverythingText(tc->Identifier);
                choiceCheck = true;
                strcat(everythingText, " = ");
                strcat(everythingText, number);
                strcat(everythingText, "\n");
                containerCount++;
                sprintf(number, "%d", containerCount-1);
                strcat(containerText, "\n# container ");
                strcat(containerText, number);
                strcat(containerText, "\n");

                strcat(containerText, "int64 ");
                toFormatString(tc->Identifier, false, false);
                strcat(containerText, "\n");
            }

            if(sequenceEnd) {
                strcpy(dataTypeHelp, "sequence");
            }
        } else if(sequenceEnd) {
            strcpy(dataTypeHelp, "sequence");
        } else if(strcmp(dataTypeHelp, "enumerated") == 0) {
            if(tc->Identifier) {
                strcat(everythingText, "int64 ");
                strcat(everythingText, toUpperIdentifier(identifierHelp));
                strcat(everythingText, "_");
                toFormatString(tc->Identifier, true, true);
                strcat(everythingText, " = ");

                if(tc->value) {
                    asn1write_value(tc->value, flags);
                } else {
                    sprintf(counterCharEnumerated, "%d", counterEnumerated);
                    strcat(everythingText, counterCharEnumerated);
                    counterEnumerated++;
                }

                strcat(everythingText, "\n");
            }
        } else if(strcmp(dataTypeHelp, "octetstring") == 0) {
            if(!choiceCheck) toFormatString(tc->Identifier, false, false);
            strcpy(dataTypeHelp, "octetstring");
            check = true;

            if(!choiceCheck) {
                if(((tc->marker.flags & EM_OPTIONAL) != EM_OPTIONAL) && level >= 1) strcat(everythingText, "\n");
                if((tc->marker.flags & EM_OPTIONAL) == EM_OPTIONAL) {
                    if(level > 0) strcat(everythingText, "\n");
                    strcat(everythingText, "# Optional Field\nbool ");
                    strcat(everythingText, toFormatAndLowerIdentifierForOptionalField(tc->Identifier));
                    strcat(everythingText, "_present 0");
                    strcat(everythingText, "\n");
                }

                strcat(everythingText, "int64[] ");
                toFormatString(tc->Identifier, false, true);
                strcat(everythingText, " ");
                asn1write_constraint(tc->Identifier, tc->constraints, flags);
                strcat(everythingText, "\n");
            } else {
                char number[20];
                sprintf(number, "%d", containerCount);
                strcat(everythingText, "int64 ");
                strcat(everythingText, identifierForContainer);
                strcat(everythingText, "_");
                choiceCheck = false;
                toUpperIdentifierForEverythingText(tc->Identifier);
                choiceCheck = true;
                strcat(everythingText, " = ");
                strcat(everythingText, number);
                strcat(everythingText, "\n");
                containerCount++;
                sprintf(number, "%d", containerCount-1);
                strcat(containerText, "\n# container ");
                strcat(containerText, number);
                strcat(containerText, "\n");

                strcat(containerText, "int64 ");
                toFormatString(tc->Identifier, false, false);
            }
        } else {
            strcat(everythingText, dataTypeHelp);
            strcat(everythingText, " ");
            toFormatString(identifierHelp, true, true);
            strcat(everythingText, "_");
            toFormatString(tc->Identifier, true, true);
            strcat(everythingText, " = ");
            if(tc->value) {
                asn1write_value(tc->value, flags);
            } else {
                asn1write_constraint(tc->Identifier, tc->constraints, flags);
            }

            strcat(everythingText, "\n");
        }
    }

    if(TQ_FIRST(&(tc->members))
       || (tc->expr_type & ASN_CONSTR_MASK)
       || tc->meta_type == AMT_OBJECT
       || tc->meta_type == AMT_OBJECTCLASS
       || tc->meta_type == AMT_OBJECTFIELD
    ) {
        asn1p_expr_t *se; /* SubExpression */
        int put_braces = (!SEQ_OF) /* Don't need 'em, if SET OF... */
                         && (tc->meta_type != AMT_OBJECTFIELD);

        TQ_FOR(se, &(tc->members), next) {
            /*
             * Print the expression as it were a stand-alone type.
             */
            asn1write_expr(asn, mod, se, flags, level + 1);
        }

        if(put_braces && TQ_FIRST(&tc->members) && tc->expr_type != ASN_BASIC_ENUMERATED) {
            choiceEnd = true;
            sequenceEnd = true;
            counterEnumerated = 0;

            isBitString = false;
        }
    }

    if(choiceEnd) {
        if(strcmp(containerText, "") != 0) {
            strcat(everythingText, containerText);
            strcat(everythingText, "\n");
            strcpy(containerText, "");
            containerCount = 0;
            choiceCheck = false;
        }
        choiceEnd = false;
    }

    if(level == 0) {
        counterEnumerated = 0;
        strcpy(identifierHelp, "");
        strcpy(fileName, dirPath);
        toFormatIdentifierForRegion(tc->Identifier);
        strcat(fileName, identifierForSequenceRegion);
        strcat(fileName, ".msg");
        fp = fopen(fileName, "w+");

        if(strcmp(containerText, "") != 0) {
            strcat(everythingText, containerText);
            strcat(everythingText, "\n");
            strcpy(containerText, "");
            containerCount = 0;
            choiceCheck = false;
        }

        char header [50000];
        strcpy(header, "#\n"
               "# Generated with ROS-Parser from vehicleCAPTAIN Toolbox (https://github.com/virtual-vehicle/vehicle_captain_asn1_parser)\n"
               "# Patrizia Neubauer (https://github.com/patrizianeubauer)\n"
               "# \n"
               "\n\n");

        strcat(header, everythingText);
        sequenceEnd = true;
        fprintf(fp, header);
        strcpy(everythingText, "");
        fclose(fp);
    }

    return 0;
}

static int asn1write_expr_dtd(asn1p_t *asn, asn1p_module_t *mod, asn1p_expr_t *expr, enum asn1write_flags flags, int level) {
    asn1p_expr_t *se;
    int expr_unordered = 0;
    int dont_involve_children = 0;

    switch(expr->meta_type) {
    case AMT_TYPE:
    case AMT_TYPEREF:
        break;
    default:
        if(expr->expr_type == A1TC_UNIVERVAL) break;
        return 0;
    }

    if(!expr->Identifier) return 0;

    if(expr->expr_type == A1TC_REFERENCE) {
        se = WITH_MODULE_NAMESPACE(expr->module, expr_ns, asn1f_find_terminal_type_ex(asn, expr_ns, expr));
        expr = se;
        dont_involve_children = 1;
    }

    if(expr->expr_type == ASN_CONSTR_CHOICE
       || expr->expr_type == ASN_CONSTR_SEQUENCE_OF
       || expr->expr_type == ASN_CONSTR_SET_OF
       || expr->expr_type == ASN_CONSTR_SET
       || expr->expr_type == ASN_BASIC_INTEGER
       || expr->expr_type == ASN_BASIC_ENUMERATED) {
        expr_unordered = 1;
    }

    if(TQ_FIRST(&expr->members)) {
        int extensible = 0;
        if(expr->expr_type == ASN_BASIC_BIT_STRING) dont_involve_children = 1;
        strcat(everythingText, " (");

        TQ_FOR(se, &(expr->members), next) {
            if(se->expr_type == A1TC_EXTENSIBLE) {
                extensible = 1;
                check = true;
                continue;
            } else if(!se->Identifier && se->expr_type == A1TC_REFERENCE) {
                asn1write_ref(se->reference, flags, level);
            } else if(se->Identifier) {
                strcat(everythingText, se->Identifier);
            }
        }

        strcat(everythingText, ")\n");
    }

    /*
     * Write the descendants (children) of the current type.
     */
    if(!dont_involve_children) {
        TQ_FOR(se, &(expr->members), next) {
            if(se->expr_type == A1TC_EXTENSIBLE) continue;
            asn1write_expr_dtd(asn, mod, se, flags, level + 1);
        }
    }

    return 0;
}

static struct counter * toSplitIdentifier(char * identifier) {
    char delimiter[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ8-";
    char delimiter2[] = "-";
    char *ptrtwo = identifier;
    char *ptrthree = identifier;
    char *ptr;
    int index = 0;
    int sum = 0;
    int namesCounter = 0;
    struct counter * ct = malloc(sizeof(struct counter));

    char typeName[strlen(identifier)];
    strcpy(typeName, identifier);
    checkAllUpper = checkIfEverythingIsUpperCaseInIdentifier(identifier);

    if(checkAllUpper) {
        ptr = strtok(typeName, delimiter2);
    } else {
        ptr = strtok(typeName, delimiter);
    }

    while(ptr != NULL) {
        sum = strlen(ptr);
        index = index + sum + 1;
        namesCounter++;
        if(checkAllUpper) {
            ptr = strtok(NULL, delimiter2);
        } else {
            ptr = strtok(NULL, delimiter);
        }
        if(ptr == NULL && namesCounter > 1) index = index - sum;
    }

    if(namesCounter > 1) index--;
    if(isupper(identifier[0]) && isupper(identifier[1]) && isupper(identifier[2]) && identifier[3] == NULL && checkAllUpper) {
        namesCounter = 1;
    } else if(isupper(identifier[0]) && isupper(identifier[1]) && isupper(identifier[2]) && identifier[3] != NULL && !checkAllUpper) {
        namesCounter = namesCounter + 3;
        index = index - 4;
    } else if(islower(ptrtwo[0]) && isupper(ptrtwo[strlen(ptrtwo)-2]) && isupper(ptrtwo[strlen(ptrtwo)-1]) && !checkAllUpper) {
        namesCounter = namesCounter + 1;
        index--;
    } else if(isupper(ptrtwo[strlen(ptrtwo)-2]) && isupper(ptrtwo[strlen(ptrtwo)-1])) {
        namesCounter++;
    } else if(islower(identifier[0])) {
        index--;
    }

    if(namesCounter == 3 && isupper(ptrtwo[strlen(ptrtwo)-2]) && isupper(ptrtwo[strlen(ptrtwo)-1]) && !checkAllUpper) {
        index = index + sum + 1;
    }

    if(identifier[index] == '-') index++;

    if(checkAllUpper) namesCounter = 1;

    ct->namesCounter = namesCounter;
    ct->index = index;

    return ct;
}

static void toFormatString(char * identifierChar, bool toUpper, bool toPrint) {
    char toCharArrayOne[2];
    char toCharArrayTwo[4];
    char helpAllIdentifier[10000];
    strcpy(helpAllIdentifier, "");

    if(identifierChar[0] != '.') {
        for(int i = 0; i < strlen(identifierChar) + 1; i++) {
            if(identifierChar[i] == '-' || identifierChar[i] == '_') {
                if(!choiceCheck) {
                    if(toPrint) strcat(helpAllIdentifier, "_");
                } else if(toPrint) strcat(containerText, "_");
            } else if(identifierChar[i+1] != NULL && islower(identifierChar[i]) && isupper(identifierChar[i+1])) {
                toCharArrayTwo[0] = identifierChar[i];
                toCharArrayTwo[1] = '_';
                toCharArrayTwo[2] = identifierChar[i+1]; i++;
                toCharArrayTwo[3] = '\0';
                strcat(helpAllIdentifier, toCharArrayTwo);
            } else {
                toCharArrayOne[0] = identifierChar[i];
                toCharArrayOne[1] = '\0';
                strcat(helpAllIdentifier, toCharArrayOne);
            }
        }

        if(isBitString) strcat(helpAllIdentifier, "_BIT");

        if(toUpper && toPrint && !choiceCheck) {
            strcat(everythingText, toUpperIdentifier(helpAllIdentifier));
        } else if(toUpper && toPrint && choiceCheck) {
            strcat(containerText, toUpperIdentifier(helpAllIdentifier));
        } else if(!toUpper && toPrint && !choiceCheck) {
            strcat(everythingText, toLowerIdentifier(helpAllIdentifier));
        } else if(!toUpper && !toPrint && !choiceCheck) {
            strcpy(identifierHelp, toUpperIdentifier(helpAllIdentifier));
        } else if(!toUpper && !toPrint && choiceCheck) {
            strcat(containerText, toLowerIdentifier(helpAllIdentifier));
        }

        if(!choiceCheck) strcpy(identifierForContainer, toUpperIdentifier(helpAllIdentifier));
    }
}

static char* toFormatAndLowerIdentifierForOptionalField(char * identifierChar) {
    int j = 0;

    for(int i = 0; i < strlen(identifierChar) + 1; i++) {
        if(identifierChar[i] == '-' || identifierChar[i] == '_') {
            identifierHelp[j] = '_'; j++;
        }

        if(((i + 1) < strlen(identifierChar)) && (((islower(identifierChar[i]) && isupper(identifierChar[i + 1])))) && identifierChar[i-1] != NULL) {
            identifierHelp[j] = tolower(identifierChar[i]); j++;
            identifierHelp[j] = '_'; j++;
            identifierHelp[j] = tolower(identifierChar[i + 1]); j++;
            i++;
        } else if(((i + 1) < strlen(identifierChar)) && (((islower(identifierChar[i]) && isupper(identifierChar[i + 1])))) && identifierChar[i-1] == NULL) {
            identifierHelp[j] = tolower(identifierChar[i]); j++;
            identifierHelp[j] = '_'; j++;
            identifierHelp[j] = tolower(identifierChar[i + 1]); j++;
            i++;
        } else if((identifierChar[i + 1] == NULL && identifierChar[i] != NULL) || (identifierChar[i - 1] == NULL && identifierChar[i] != NULL)) {
            identifierHelp[j] = tolower(identifierChar[i]); j++;
        } else if(islower(identifierChar[i])) {
            identifierHelp[j] = tolower(identifierChar[i]); j++;
        } else {
            identifierHelp[j] = tolower(identifierChar[i]); j++;
        }
        /*else if(i < strlen((identifierChar))) {
            //identifierHelp[j] = '_'; j++;
            identifierHelp[j] = tolower(identifierChar[i]); j++;
        }*/
    }

    identifierHelp[j] = '\0';
    return identifierHelp;
}

static void toFormatAndLowerString(char * identifierString, enum asn1write_flags flags, bool regionalCheck) {

    if(regionalCheck) {
        strcpy(identifierString, identifierForSequenceRegion);
    }

    struct counter * ct = toSplitIdentifier(identifierString);

    if(ct->namesCounter > 1) {
        char * stringTypeTwo = malloc(strlen(identifierString) - ct->index + 1);
        strncpy(stringTypeTwo, identifierString + ct->index, strlen(identifierString) - ct->index);
        stringTypeTwo[strlen(identifierString) - ct->index] = '\0';
        strcat(everythingText, toLowerIdentifier(stringTypeTwo));
        free(stringTypeTwo);
    } else {
        strcat(everythingText, toLowerIdentifier(identifierString));
    }

    free(ct);
    check = true;
}

static void toFormatIdentifierForRegion(char* identifierChar) {
    char ident [100];
    int j = 0;

    for(int i = 0; i < strlen(identifierChar) + 1; i++) {
        if(identifierChar[i] == '-' || identifierChar[i] == '_') {
            i++;
            ident[j] = toupper(identifierChar[i]); j++; i++;
        }

        ident[j] = identifierChar[i]; j++;
    }

    if(islower(ident[0])) ident[0] = toupper(ident[0]);
    strcpy(identifierForSequenceRegion, ident);
}

static char* toUpperIdentifier(char * identifier) {
    char *array = malloc(strlen(identifier)+1);

    for(int i = 0; i < strlen(identifier) ; i++) {
        if(identifier[i] == '-') array[i] = '_';
        else array[i] = toupper(identifier[i]);
    }

    array[strlen(identifier)] = '\0';

    return array;
}

static void toUpperIdentifierForEverythingText(char* identifierChar) {
    char toCharArrayOne[2];
    char toCharArrayTwo[4];
    char helpAllIdentifier[10000];
    strcpy(helpAllIdentifier, "");

    if(identifierChar[0] != '.') {
        for(int i = 0; i < strlen(identifierChar) + 1; i++) {
            if(identifierChar[i] == '-' || identifierChar[i] == '_') {
                strcat(helpAllIdentifier, "_");
            } else if(identifierChar[i + 1] != NULL
                      && islower(identifierChar[i])
                      && isupper(identifierChar[i + 1])) {
                toCharArrayTwo[0] = identifierChar[i];
                toCharArrayTwo[1] = '_';
                toCharArrayTwo[2] = identifierChar[i + 1];
                i++;
                toCharArrayTwo[3] = '\0';
                strcat(helpAllIdentifier, toCharArrayTwo);
            } else {
                toCharArrayOne[0] = identifierChar[i];
                toCharArrayOne[1] = '\0';
                strcat(helpAllIdentifier, toCharArrayOne);
            }
        }
    }

    strcat(everythingText, toUpperIdentifier(helpAllIdentifier));
}

static char* toLowerIdentifier(char * identifierChar) {
    char *array = malloc(strlen(identifierChar)+1);

    for(int i = 0; i < strlen(identifierChar) ; i++) {
        array[i] = tolower(identifierChar[i]);
    }

    array[strlen(identifierChar)] = '\0';

    return array;
}

static void toUpperIdentifierForSequenceOf(char * stringTypeOne) {

    char helpArray[strlen(stringTypeOne)];
    int j = 0;

    for(int i = 0; i < strlen(stringTypeOne); i++) {
        if(stringTypeOne[i] == '-') {
            i++;
        }
        else {
            helpArray[j] = stringTypeOne[i];
            j++;
        }
    }
    helpArray[j] = '\0';

    strcat(everythingText, helpArray);
}

static void toFormattedSequenceOf(asn1p_expr_t *tc, enum asn1write_flags flags, bool regionalCheck, int level) {
    char identifierString [100];

    if(regionalCheck) {
        strcpy(identifierString, "Reg");
        strcat(identifierString, identifierHelp);
        strcpy(followingTextSequenceOf, "");
        strcat(followingTextSequenceOf, identifierString);
        strcat(followingTextSequenceOf, "[] ");
        if(tc->Identifier) strcat(followingTextSequenceOf, tc->Identifier);
    } else {
        int j = 0, minusIndex;
        for(int i = 0; i < strlen(tc->Identifier); i++) {
            if(tc->Identifier[i] != '-') {
                identifierString[j] = tc->Identifier[i];
                j++;
            } else {
                minusIndex = i;
            }
        }
        identifierString[j] = '\0';

        struct counter * ct = toSplitIdentifier(identifierString);

        if(ct->namesCounter > 1) {
            char * stringTypeOne = malloc(ct->index + 1);
            strncpy(stringTypeOne, identifierString, ct->index);
            stringTypeOne[ct->index] = '\0';

            strcat(followingTextSequenceOf, "[] ");

            char * stringTypeTwo = malloc(strlen(identifierString) - ct->index + 1);
            strncpy(stringTypeTwo, identifierString + ct->index, strlen(identifierString) - ct->index);
            stringTypeTwo[strlen(identifierString) - ct->index] = '\0';
            stringTypeTwo = toLowerIdentifier(stringTypeTwo);
            strcat(followingTextSequenceOf, stringTypeTwo);
            free(stringTypeTwo);
            free(stringTypeOne);
        } else {
            strcat(followingTextSequenceOf, "[] ");
            strcat(followingTextSequenceOf, toLowerIdentifier(identifierString));
        }


    }

    strcat(followingTextSequenceOf, " ");

    if(tc->lhs_params) {
        asn1write_params(tc->lhs_params, flags);
    }

    check = true;
}

static bool checkIfEverythingIsUpperCaseInIdentifier(char * identifier) {
    for(int i = 0; i < strlen(identifier); i++) {
        if(islower(identifier[i])) return false;
    }

    return true;
}