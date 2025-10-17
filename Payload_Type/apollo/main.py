import mythic_container
from apollo.mythic import *
from apollo.translator import ApolloTranslator

# Register the translator container
mythic_container.mythic_service.add_translation_container(ApolloTranslator)

mythic_container.mythic_service.start_and_run_forever()