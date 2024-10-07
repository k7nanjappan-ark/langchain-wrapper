import CloudProviders from '../cloud-providers';
import {
  GCP_DETECT_PERMISSIONS_PROMPT,
  GCP_GENERATE_CUSTOM_ROLES_PROMPT,
} from './gcp';
import {
  AWS_DETECT_STATEMENTS_PROMPT,
  AWS_GENERATE_POLICIES_PROMPT,
  AWS_GENERATE_POLICIES_PROMPT_FROM_SNIPPETS
} from './aws';
import { ChatPromptTemplate } from 'langchain/prompts';

type Prompts = {
  readonly [k in CloudProviders]: {
    [j in string]: ChatPromptTemplate;
  };
};

const cpPrompts: Prompts = {
  aws: {
    DETECT_STATEMENTS_PROMPT: AWS_DETECT_STATEMENTS_PROMPT,
    GENERATE_POLICIES_PROMPT: AWS_GENERATE_POLICIES_PROMPT,
    GENERATE_POLICIES_PROMPT_FROM_SNIPPETS: AWS_GENERATE_POLICIES_PROMPT_FROM_SNIPPETS,
  },
  gcp: {
    DETECT_PERMISSIONS_PROMPT: GCP_DETECT_PERMISSIONS_PROMPT,
    GENERATE_CUSTOM_ROLES_PROMPT: GCP_GENERATE_CUSTOM_ROLES_PROMPT,
  },
};

export default cpPrompts;
