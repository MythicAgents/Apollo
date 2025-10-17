import json
import logging
from mythic_container.TranslationBase import *

logging.basicConfig(level=logging.INFO)


class ApolloTranslator(TranslationContainer):
    name = "ApolloTranslator"
    description = "Translator for Apollo agent"
    author = "@djhohnstein, @its_a_feature_"

    async def translate_to_c2_format(self, inputMsg: TrMythicC2ToCustomMessageFormatMessage) -> TrMythicC2ToCustomMessageFormatMessageResponse:
        """
        Handle messages coming from the C2 server destined for Agent.
        C2 --(this message)--> Agent
        
        Since Apollo uses mythic_encrypts=True and JSON serialization,
        this is a pass-through translator that doesn't modify the message format.
        """
        response = TrMythicC2ToCustomMessageFormatMessageResponse(Success=True)
        
        # Pass through the message without modification
        # Apollo handles JSON serialization internally
        response.Message = inputMsg.Message
        
        return response

    async def translate_from_c2_format(self, inputMsg: TrCustomMessageToMythicC2FormatMessage) -> TrCustomMessageToMythicC2FormatMessageResponse:
        """
        Handle messages coming from the Agent destined for C2.
        Agent --(this message)--> C2
        
        Since Apollo uses mythic_encrypts=True and JSON serialization,
        this is a pass-through translator that doesn't modify the message format.
        """
        response = TrCustomMessageToMythicC2FormatMessageResponse(Success=True)
        
        # Pass through the message without modification
        # Apollo handles JSON serialization internally
        response.Message = inputMsg.Message
        
        return response
