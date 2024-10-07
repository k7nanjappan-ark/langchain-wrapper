import { AWSTypes } from '../../types';

function getServiceFromAction(action: string) {
    return action.split(":")[0];
}


function deduplicateArray(arr: string[]) {
    return Array.from(new Set(arr));
}

export function deduplicate(
    policies: AWSTypes.PolicyDocument[]
) {
    const deduplicatedPolicies: AWSTypes.PolicyDocument[] = [];
    const serviceEffectMap: { [key: string]: AWSTypes.Statement } = {};

    Object.values(policies).forEach((policy) => {
        const version = policy.Version;
        const id = policy.Id;

        policy.Statement.forEach((statement: AWSTypes.Statement) => {
            const effect = statement.Effect;
            const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
            const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];

            actions.forEach((action: string) => {
                const service = getServiceFromAction(action);
                const key = `${service}-${effect}`;

                if (!serviceEffectMap[key]) {
                    serviceEffectMap[key] = {
                        Version: version,
                        Id: id,
                        Sid: statement.Sid,
                        Effect: effect,
                        Action: [],
                        Resource: [],
                    };
                }

                serviceEffectMap[key].Action = deduplicateArray([
                    ...serviceEffectMap[key].Action,
                    action,
                ]);

                serviceEffectMap[key].Resource = deduplicateArray([
                    ...serviceEffectMap[key].Resource,
                    ...resources,
                ]);
            });
        });
    });

    Object.values(serviceEffectMap).forEach((policy) => {
        const combinedPolicy: AWSTypes.PolicyDocument = {
            Version: policy.Version,
            Id: policy.Id,
            Statement: [{
                Sid: policy.Sid,
                Effect: policy.Effect,
                Action: policy.Action,
                Resource: policy.Resource.length > 1 && policy.Resource.includes("*") ? policy.Resource.filter((item: string) => item !== "*") : policy.Resource,
            }],
        }
        deduplicatedPolicies.push(combinedPolicy);
    });

    return deduplicatedPolicies;
}
