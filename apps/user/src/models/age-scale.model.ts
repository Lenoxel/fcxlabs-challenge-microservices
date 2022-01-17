import { AgeScale } from '../enums/age-scale.enum';

export class AgeScaleClass {
  private start = '';
  private end = '';

  public constructor(ageScaleType: AgeScale) {
    this.setDates(ageScaleType);
  }

  getStart() {
    return this.start;
  }

  getEnd() {
    return this.end;
  }

  setDates(ageScaleType: AgeScale) {
    const startDate = new Date();
    const endDate = new Date();

    const rangeDate = {
      Between18And26: () => {
        startDate.setFullYear(startDate.getFullYear() - 26);
        endDate.setFullYear(endDate.getFullYear() - 18);
        this.start = startDate.toISOString();
        this.end = endDate.toISOString();
      },
      Between25And31: () => {
        startDate.setFullYear(startDate.getFullYear() - 31);
        endDate.setFullYear(endDate.getFullYear() - 25);
        this.start = startDate.toISOString();
        this.end = endDate.toISOString();
      },
      Between30And36: () => {
        startDate.setFullYear(startDate.getFullYear() - 36);
        endDate.setFullYear(endDate.getFullYear() - 30);
        this.start = startDate.toISOString();
        this.end = endDate.toISOString();
      },
      Between35And41: () => {
        startDate.setFullYear(startDate.getFullYear() - 41);
        endDate.setFullYear(endDate.getFullYear() - 35);
        this.start = startDate.toISOString();
        this.end = endDate.toISOString();
      },
      GreaterThan40: () => {
        endDate.setFullYear(endDate.getFullYear() - 40);
        this.end = endDate.toISOString();
      },
    };

    rangeDate[ageScaleType].call();
  }
}
