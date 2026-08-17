/*
 * ConfigValidation.h
 * 
 * Configuration validation for SCADASentry
 * Validates all settings from Config.h at startup
 * 
 * GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
 * https://github.com/Xorlent/SCADASentry
 */

#ifndef CONFIG_VALIDATION_H
#define CONFIG_VALIDATION_H

// Validate configuration at startup
// Returns false if critical errors found, true otherwise
bool validateConfiguration();

#endif
