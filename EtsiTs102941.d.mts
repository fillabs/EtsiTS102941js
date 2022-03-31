import type { Ieee1609Dot2Data } from 'Ieee1609Dot2js';
import type {iEnumerated, iSequence} from 'asnjs'

declare module "EtsiTs102941js" {
    export class EnrolmentResponseCode extends iEnumerated {
    }
    export class AuthorizationResponseCode extends iEnumerated{
    }
    export class AuthorizationValidationResponseCode extends iSequence{
    }
    export class EtsiTs102941DataContent extends iSequence{
        enrolmentRequest?: Ieee1609Dot2Data
        enrolmentResponse?: any
        authorizationRequest?:any
        authorizationResponse?:any
        certificateRevocationList?:any
        certificateTrustListTlm?:any
        certificateTrustListRca?:any
        authorizationValidationRequest?:any
        authorizationValidationResponse?:any
        caCertificateRequest?:any
    }
    export class EtsiTs102941Data extends iSequence{
        version: number;
        content: EtsiTs102941DataContent;
    }
}