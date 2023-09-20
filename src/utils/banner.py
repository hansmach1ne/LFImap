import argparse

# Custom HelpFormatter
class BannerHelpFormatter(argparse.HelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=30, width=100)

    def format_help(self):
        # Get the default help message
        help_text = super().format_help()

        # Define a banner message
        banner = '''
  _      ______ _____                       
 | |    |  ____|_   _|                      
 | |    | |__    | |  _ __ ___   __ _ _ __  
 | |    |  __|   | | | '_ ` _ \ / _` | '_ \ 
 | |____| |     _| |_| | | | | | (_| | |_) |
 |______|_|    |_____|_| |_| |_|\__,_| .__/ 
                                     | |    
                                     |_|    

                                - by mach1ne\n\n\n'''

        # Add the banner to the help message
        return banner + help_text
