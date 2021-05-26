import * as Ieee1609Dot2 from 'Ieee1609Dot2js';
import {Uint8, Choice, Sequence, SequenceOf, Enumerated, Boolean, Integer, IA5String } from 'asn1js';

class EnrolmentResponseCode extends Enumerated([
    'ok',
    'cantparse', //valid for any structure
    'badcontenttype', //not encrypted, not signed, not enrolmentrequest
    'imnottherecipient', //the “recipients” doesn’t include me
    'unknownencryptionalgorithm', //either kexalg or contentencryptionalgorithm
    'decryptionfailed', //works for ECIES_HMAC and AES_CCM
    'unknownits', //can’t retrieve the ITS from the itsId
    'invalidsignature', //signature verification of the request fails
    'invalidencryptionkey', //signature is good, but the responseEncryptionKey is bad
    'baditsstatus', //revoked, not yet active
    'incompleterequest', //some elements are missing
    'deniedpermissions', //requested permissions are not granted
    'invalidkeys', //either the verification_key of the encryption_key is bad
    'deniedrequest', //any other reason ?
    Enumerated.Extension
]) { }

class AuthorizationResponseCode extends Enumerated([
    'ok',
    //ITS -> AA
    'its_aa_cantparse', //valid for any structure
    'its_aa_badcontenttype', //not encrypted, not signed, not authorizationrequest
    'its_aa_imnottherecipient', //the “recipients” of the outermost encrypted data doesn’t include me
    'its_aa_unknownencryptionalgorithm', //either kexalg or contentencryptionalgorithm
    'its_aa_decryptionfailed', //works for ECIES_HMAC and AES_CCM
    'its_aa_keysdontmatch', //HMAC keyTag verification fails
    'its_aa_incompleterequest', //some elements are missing
    'its_aa_invalidencryptionkey', //the responseEncryptionKey is bad
    'its_aa_outofsyncrequest', //signingTime is outside acceptable limits
    'its_aa_unknownea', //the EA identified by eaId is unknown to me
    'its_aa_invalidea', //the EA certificate is revoked
    'its_aa_deniedpermissions', //I, the AA, deny the requested permissions
    //AA -> EA
    'aa_ea_cantreachea', //the EA is unreachable(network error ?)
    //EA -> AA
    'ea_aa_cantparse', //valid for any structure
    'ea_aa_badcontenttype', //not encrypted, not signed, not authorizationrequest
    'ea_aa_imnottherecipient', //the “recipients” of the outermost encrypted data doesn’t include me
    'ea_aa_unknownencryptionalgorithm', //either kexalg or contentencryptionalgorithm
    'ea_aa_decryptionfailed', //works for ECIES_HMAC and AES_CCM
    //TODO: to be continued...
    'invalidaa', //the AA certificate presented is invalid / revoked / whatever
    'invalidaasignature', //the AA certificate presented can’t validate the request signature
    'wrongea', //the encrypted signature doesn’t designate me as the EA
    'unknownits', //can’t retrieve the EC / ITS in my DB
    'invalidsignature', //signature verification of the request by the EC fails
    'invalidencryptionkey', //signature is good, but the key is bad
    'deniedpermissions', //permissions not granted
    'deniedtoomanycerts', //parallel limit
    Enumerated.Extension
]) { }

class AuthorizationValidationResponseCode extends Enumerated([
    'ok',
    'cantparse', //valid for any structure
    'badcontenttype', //not encrypted, not signed, not permissionsverificationrequest
    'imnottherecipient', //the “recipients” of the outermost encrypted data doesn’t include me
    'unknownencryptionalgorithm', //either kexalg or contentencryptionalgorithm
    'decryptionfailed', //works for ECIES - HMAC and AES - CCM
    'invalidaa', //the AA certificate presented is invalid / revoked / whatever
    'invalidaasignature', //the AA certificate presented can’t validate the request signature
    'wrongea', //the encrypted signature doesn’t designate me as the EA
    'unknownits', //can’t retrieve the EC / ITS in my DB
    'invalidsignature', //signature verification of the request by the EC fails
    'invalidencryptionkey', //signature is good, but the responseEncryptionKey is bad
    'deniedpermissions', //requested permissions not granted
    'deniedtoomanycerts', //parallel limit
    'deniedrequest', //any other reason ?
    Enumerated.Extension
]) { }

class PublicKeys extends Sequence([
    {
        name: 'verificationKey',
        type: Ieee1609Dot2.PublicVerificationKey
    }, {
        name: 'encryptionKey',
        optional: true,
        type: Ieee1609Dot2.PublicEncryptionKey
    }
]) { }

class CertificateSubjectAttributes extends Sequence([
    {
        name: 'id',
        optional: true,
        type: Ieee1609Dot2.CertificateId
    }, {
        name: 'validityPeriod',
        optional: true,
        type: Ieee1609Dot2.ValidityPeriod
    }, {
        name: 'region',
        optional: true,
        type: Ieee1609Dot2.GeographicRegion
    }, {
        name: 'assuranceLevel',
        optional: true,
        type: Ieee1609Dot2.SubjectAssurance
    }, {
        name: 'appPermissions',
        optional: true,
        type: SequenceOf(Ieee1609Dot2.PsidSsp)
    }, {
        name: 'certIssuePermissions',
        optional: true,
        type: SequenceOf(Ieee1609Dot2.PsidGroupPermissions)
    }, {
        extension: true
    }
]) { }

class SharedAtRequest extends Sequence([
    {
        name: 'eaId',
        type: Ieee1609Dot2.HashedId8
    }, {
        name: 'keyTag',
        type: Ieee1609Dot2.OctetString16
    }, {
        name: 'certificateFormat',
        type: Uint8
    }, {
        name: 'requestedSubjectAttributes',
        type: CertificateSubjectAttributes
    }, {
        extension: true
    }
]) { }

class ToBeSignedCrl extends Sequence([
    {
        name: 'version',
        type: Integer()
    }, {
        name: 'thisUpdate',
        type: Ieee1609Dot2.Time32
    }, {
        name: 'nextUpdate',
        type: Ieee1609Dot2.Time32
    }, {
        name: 'entries',
        type: SequenceOf(Ieee1609Dot2.HashedId8)
    }, {
        extension:true
    }
]) { }

class CtlFormat extends Sequence([
    {
        name: 'version',
        type: Integer()
    }, {
        name: 'nextUpdate',
        type: Ieee1609Dot2.Time32
    }, {
        name: 'isFullCtl',
        type: Boolean
    }, {
        name: 'ctlSequence',
        type: Uint8
    }, {
        name: 'ctlCommands',
        type: SequenceOf(Choice([
            {
                name: 'add',
                type: Choice([
                    {
                        name: 'rca', type: Sequence([
                            { name: 'selfsignedRootCa', type: Ieee1609Dot2.Certificate },
                            { name: 'linkRootCaCertificate', optional: true, type: Ieee1609Dot2.Certificate }
                        ])
                    }, {
                        name: 'ea', type: Sequence([
                            { name: 'eaCertificate', type: Ieee1609Dot2.Certificate },
                            { name: 'aaAccessPoint', type: IA5String },
                            { name: 'itsAccessPoint', optional: true, type: IA5String }
                        ])
                    }, {
                        name: 'aa', type: Sequence([
                            { name: 'aaCertificate', type: Ieee1609Dot2.Certificate },
                            { name: 'accessPoint', type: IA5String }
                        ])
                    }, {
                        name: 'dc', type: Sequence([
                            { name: 'url', type: IA5String },
                            { name: 'cert', optional: true, type: SequenceOf(Ieee1609Dot2.HashedId8) }
                        ])
                    }, {
                        name: 'tlm', type: Sequence([
                            { name: 'selfSignedTLMCertificate', type: Ieee1609Dot2.Certificate },
                            { name: 'linkTLMCertificate', type: Ieee1609Dot2.Certificate, optional: true },
                            { name: 'accessPoint', type: IA5String }
                        ])
                    }, {
                        extension:true
                    }
                ])
            }, {
                name: 'delete',
                type: Choice([
                    { name: 'cert', type: Ieee1609Dot2.HashedId8 },
                    { name: 'dc', type: IA5String },
                    { extension:true }
                ])
            }, {
                extension: true
            }
        ]))
    }, {
        extension: true
    }
]) { }

class CaCertificateRequest extends Sequence([
    {
        name: 'publicKeys',
        type: PublicKeys
    }, {
        name: 'requestedSubjectAttributes',
        type: CertificateSubjectAttributes
    }, {
        extension: true
    }
]) { }

class EcSignature extends Choice([
    {
        name: 'encryptedEcSignature',
        type: Ieee1609Dot2.Data
    }, {
        name: 'ecSignature',
        type: Ieee1609Dot2.Data
    }
]) { }

export class EtsiTs102941Data extends Sequence([
    {
        name: 'version',
        type: Uint8,
    }, {
        name: 'content',
        type: Choice([
            {
                name: 'enrolmentRequest',
                type: Ieee1609Dot2.Data
            }, {
                name: 'enrolmentResponse',
                type: Sequence([
                    {
                        name: 'requestHash',
                        type: Ieee1609Dot2.OctetString16
                    }, {
                        name: 'responseCode',
                        type: EnrolmentResponseCode
                    }, {
                        name: 'certificate',
                        optional: true,
                        type: Ieee1609Dot2.Certificate
                    }, {
                        extension:true
                    }
                ])
            }, {
                name: 'authorizationRequest',
                type: Sequence([
                    {
                        name: 'publicKeys',
                        type: PublicKeys
                    }, {
                        name: 'hmacKey',
                        type: Ieee1609Dot2.OctetString32
                    }, {
                        name: 'sharedAtRequest',
                        type: SharedAtRequest
                    }, {
                        name: 'ecSignature',
                        type: EcSignature
                    }, {
                        extension:true
                    }
                ])
            }, {
                name: 'authorizationResponse',
                type: Sequence([
                    {
                        name: 'requestHash',
                        type: Ieee1609Dot2.OctetString16
                    }, {
                        name: 'responseCode',
                        type: AuthorizationResponseCode
                    }, {
                        name: 'certificate',
                        optional: true,
                        type: Ieee1609Dot2.Certificate
                    }, {
                        extension: true
                    }
                ])
            }, {
                name: 'certificateRevocationList',
                type: ToBeSignedCrl
            }, {
                name: 'certificateTrustListTlm',
                type: CtlFormat
            }, {
                name: 'certificateTrustListRca',
                type: CtlFormat
            }, {
                name: 'authorizationValidationRequest',
                type: Sequence([
                    {
                        name: 'sharedAtRequest',
                        type: SharedAtRequest
                    }, {
                        name: 'ecSignature',
                        type: EcSignature
                    }, {
                        extension:true
                    }
                ])
            }, {
                name: 'authorizationValidationResponse',
                type: Sequence([
                    {
                        name: 'requestHash',
                        type: Ieee1609Dot2.OctetString16
                    }, {
                        name: 'responseCode',
                        type: AuthorizationValidationResponseCode
                    }, {
                        name: 'confirmedSubjectAttributes',
                        optional: true,
                        type: CertificateSubjectAttributes
                    }, {
                        extension: true
                    }
                ])
            }, {
                name: 'caCertificateRequest',
                type: CaCertificateRequest
            }, {
                estension:true
            }
        ])
    }
]) { }
