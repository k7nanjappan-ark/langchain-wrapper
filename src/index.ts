import * as TextSplitters from 'langchain/text_splitter';
import { TextLoader } from 'langchain/document_loaders/fs/text';

export { default as JSONSchemas } from './utils/json-schemas';
export { default as CloudProviders } from './utils/cloud-providers';
export { default as OpenAIModels } from './utils/models';
export * as ZodSchemas from './utils/zod-types/aws-policy';
export * as Types from './types';
export const LangChain = {
  TextSplitters,
  TextLoader,
};
export {
  getPoliciesFromStatements,
  getStatementsFromCode,
} from './services/openai';
